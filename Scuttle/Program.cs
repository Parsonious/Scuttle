using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;

using Scuttle.Encoders;
using Scuttle.Models;
using Scuttle.Services;
using Scuttle.Models.Art;
using Scuttle.Interfaces;
using Scuttle.Models.Configuration;
using Scuttle.Configuration;
using Microsoft.Extensions.Logging.Console;

class Program
{
    private readonly ConfigurationService _configService;
    private readonly EncryptionService _encryptionService;
    private readonly FileService _fileService;
    private readonly DisplayService _displayService;
    private readonly ILogger<Program> _logger;
    private readonly ArgumentParser _parser;
    private readonly FileEncryptionService _fileEncryptionService;
    private readonly AlgorithmRegistry _algorithmRegistry;
    private readonly EncryptionFactory _encryptionFactory;

    public Program(
        ConfigurationService configService,
        EncryptionService encryptionService,
        FileService fileService,
        DisplayService displayService,
        ILogger<Program> logger,
        ArgumentParser parser,
        FileEncryptionService fileEncryptionService,
        AlgorithmRegistry algorithmRegistry,
        EncryptionFactory encryptionFactory)
    {
        _configService = configService;
        _encryptionService = encryptionService;
        _fileService = fileService;
        _displayService = displayService;
        _logger = logger;
        _parser = parser;
        _fileEncryptionService = fileEncryptionService;
        _algorithmRegistry = algorithmRegistry;
        _encryptionFactory = encryptionFactory;
    }

    public static async Task Main(string[] args)
    {
        try
        {
            using var host = CreateHostBuilder(args).Build();

            // Get the Program instance from the DI container
            var program = host.Services.GetRequiredService<Program>();
            await program.RunAsync(args);
        }
        catch ( Exception ex )
        {
            Console.Error.WriteLine($"Fatal error: {ex.Message}");
            Environment.Exit(1);
        }
    }

    private static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureAppConfiguration((hostContext, config) =>
            {
                config.SetBasePath(AppContext.BaseDirectory);
                config.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
                config.AddEnvironmentVariables("SCUTTLE_");
                config.AddCommandLine(args);
            })
            .ConfigureLogging((hostContext, logging) =>
            {
                logging.ClearProviders();
                logging.AddConfiguration(hostContext.Configuration.GetSection("Logging"));

                // Add filter to suppress specific log sources at Information level in the console
                logging.AddFilter<ConsoleLoggerProvider>("Scuttle.Services.FileEncryptionService", LogLevel.Warning);
                logging.AddFilter<ConsoleLoggerProvider>("Scuttle.Program", LogLevel.Warning);

                // Keep default filters for other namespaces
                logging.AddFilter("Microsoft", LogLevel.Warning);
                logging.AddFilter("System", LogLevel.Warning);
                logging.AddFilter("Scuttle", LogLevel.Information);

                // Add console logger after filters
                logging.AddConsole();
            })
            .ConfigureServices((hostContext, services) =>
            {
                // Register configurations
                services.Configure<EncryptionConfig>(hostContext.Configuration.GetSection("Encryption"));
                services.Configure<EncoderConfig>(hostContext.Configuration.GetSection("Encoders"));
                services.Configure<AlgorithmConfig>(hostContext.Configuration.GetSection("Algorithms"));

                //Register Configurations
                services.AddSingleton(hostContext.Configuration.GetSection("Encryption").Get<EncryptionConfig>() ?? new EncryptionConfig());
                services.AddSingleton(hostContext.Configuration.GetSection("Encoders").Get<EncoderConfig>() ?? new EncoderConfig());
                services.AddSingleton(hostContext.Configuration.GetSection("Algorithms").Get<AlgorithmConfig>() ?? new AlgorithmConfig());

                // Register core services
                services.AddSingleton<AlgorithmIdentifier>();
                services.AddSingleton<EncryptionFactory>();
                services.AddSingleton<ConfigurationService>();
                services.AddSingleton<AlgorithmRegistry>();
                services.AddSingleton<PaddingService>();
                services.AddSingleton<ArgumentParser>();
                services.AddSingleton<EncryptionService>();
                services.AddSingleton<DisplayService>();
                services.AddSingleton<FileEncryptionService>();
                services.AddSingleton<FileService>();

                services.AddSingleton<IEncoder>(provider => {
                    var config = provider.GetRequiredService<EncryptionConfig>() ?? new EncryptionConfig { DefaultEncoder = "base64" };
                    return config.DefaultEncoder?.ToLower() switch
                    {
                        "base85" => new Base85Encoder(),
                        "base65536" => new Base65536Encoder(),
                        _ => new Base64Encoder(),
                    };
                });
                //Transients
                services.AddTransient<Util>();
                
                // Register the main application class
                services.AddSingleton<Program>();
            });

    private async Task RunAsync(string[] args)
    {
        var options = _parser.Parse(args);

        try
        {
            if ( !options.Validate(out string error) )
            {
                _logger.LogError(error);
                return;
            }

            // Handle special commands first - using early returns to avoid nesting
            if ( options.ShowVersion )
            {
                ShowVersion();
                return;
            }

            if ( options.ListAlgorithms )
            {
                _displayService.DisplayEncryptionMethods();
                return;
            }

            if ( options.ListEncoders )
            {
                _displayService.DisplayEncodingMethods();
                return;
            }

            if ( options.BatchFile != null )
            {
                await ProcessBatchFile(options.BatchFile);
                return;
            }

            // Check for interactive mode
            if ( options.IsInteractiveMode )
            {
                await RunInteractiveModeAsync();
                return;
            }

            // Process CLI operation
            await ProcessSingleOperation(options);
        }
        catch ( Exception ex )
        {
            _logger.LogError(ex, "Operation failed");
            if ( !options.Silent )
            {
                throw;
            }
        }
    }

    private async Task RunInteractiveModeAsync()
    {
        _displayService.DisplayWelcomeBanner();

        bool continueProgram = true;
        while ( continueProgram )
        {
            try
            {
                var mode = DisplayService.SelectOperationMode();
                var input = DisplayService.SelectInputType();

                var options = new CliOptions
                {
                    InputType = input,
                    Mode = mode,
                    IsInteractiveMode = true
                };
                if ( options.InputType == "file" )
                {
                    await ProcessSingleOperation(options);
                }
                else
                {
                    await ProcessSingleOperation(options);
                }
                }
            catch ( Exception ex )
            {
                _logger.LogError(ex, "Operation failed");
                Console.WriteLine($"\nAn error occurred: {ex.Message}");
            }

            continueProgram = DisplayService.YesNoPrompt();
            if ( continueProgram )
            {
                Console.Clear();
                _displayService.DisplayWelcomeBanner();
            }
        }

        Console.WriteLine("\nThank you for using the Scuttle. Press any key to exit.");
        Console.ReadKey();
    }

    private async Task ProcessSingleOperation(CliOptions options)
    {
        try
        {
            // First check if this is a file operation
            if ( options.InputType == "file" || !string.IsNullOrEmpty(options.InputFile) )
            {
                await ProcessFileOperation(options);
                return;
            }

            // Handle text-based operations
            switch ( options.Mode?.ToLower() )
            {
                case "encrypt":
                    await PerformEncryptionAsync(options);
                    break;
                case "decrypt":
                    await PerformDecryptionAsync(options);
                    break;
                default:
                    throw new ArgumentException("Invalid mode specified");
            }
        }
        catch ( Exception ex )
        {
            _logger.LogError(ex, "Operation failed");
            if ( !options.Silent )
            {
                throw;
            }
        }
    }
    // In Program.cs
    private async Task ProcessFileOperation(CliOptions options)
    {
        try
        {
            // Check if we have the required paths
            if ( string.IsNullOrEmpty(options.InputFile) )
            {
                options.InputFile = _displayService.PromptForFilePath("Enter the path to the input file:");
            }

            bool isEncrypting = options.Mode?.ToLower() == "encrypt";

            if ( string.IsNullOrEmpty(options.OutputFile) )
            {
                if ( isEncrypting )
                {
                    // For encryption, let the service determine the new extension
                    options.OutputFile = null; // We'll set it later
                }
                else
                {
                    // For decryption, try to extract a sensible extension
                    string inputFileName = Path.GetFileNameWithoutExtension(options.InputFile);
                    string directory = Path.GetDirectoryName(options.InputFile) ?? string.Empty;
                    string defaultExt;

                    // Check if the filename without extension contains another extension
                    // This would happen if the file was named like "document.pdf.enc"
                    if ( Path.HasExtension(inputFileName) )
                    {
                        // Use the embedded extension as our output format and avoid duplication
                        options.OutputFile = Path.Combine(directory,
                            Path.GetFileNameWithoutExtension(inputFileName) +
                            Path.GetExtension(inputFileName));
                    }
                    else
                    {
                        // No embedded extension, so use a generic one
                        defaultExt = ".decrypted";
                        options.OutputFile = _displayService.PromptForOutputPath(options.InputFile, defaultExt);
                    }
                }
            }

            IEncryption encryption;

            if ( isEncrypting )
            {
                // For encryption, get algorithm and encoder as before
                var algorithm = options.Algorithm != null
                    ? _configService.GetAlgorithmMetadata(options.Algorithm)
                    : _displayService.SelectEncryptionAlgorithm();

                var encoderMetadata = options.Encoder != null
                    ? _configService.GetAllEncoders().First(e => e.Name == options.Encoder)
                    : _displayService.SelectEncodingMethod();

                // Create encryption instance
                var encoder = _configService.GetEncoder(encoderMetadata.Name);
                encryption = _algorithmRegistry.CreateAlgorithm(algorithm.Name, encoder);

                // If no output file was specified, create one with the appropriate extension
                if ( string.IsNullOrEmpty(options.OutputFile) )
                {
                    options.OutputFile = _fileEncryptionService.GetEncryptedFilePath(options.InputFile, encryption);
                }
            }
            else
            {
                // For decryption, try to detect the algorithm from the file
                (string algorithmId, _) = await _fileEncryptionService.DetectEncryptionAlgorithmAsync(options.InputFile);

                if ( !string.IsNullOrEmpty(algorithmId) )
                {
                    try
                    {
                        // Found the algorithm in the file header - log at info level for user
                        var displayName = _fileEncryptionService.GetAlgorithmDisplayName(algorithmId);
                        Console.WriteLine($"\nUsing detected algorithm: {displayName}");

                        // Get the corresponding algorithm
                        var algorithm = _configService.GetAlgorithmById(algorithmId);
                        var encoder = _configService.GetDefaultEncoder(algorithm.Name);
                        encryption = _algorithmRegistry.CreateAlgorithm(algorithm.Name, encoder);
                    }
                    catch ( Exception ex )
                    {
                        // Log at debug level only
                        _logger.LogDebug(ex, "Error creating algorithm with ID {AlgorithmId}", algorithmId);

                        // Couldn't use detected algorithm, ask user
                        Console.WriteLine("Could not use the detected algorithm. Please select manually.");

                        var algorithm = options.Algorithm != null
                            ? _configService.GetAlgorithmMetadata(options.Algorithm)
                            : _displayService.SelectEncryptionAlgorithm();

                        var encoderMetadata = options.Encoder != null
                            ? _configService.GetAllEncoders().First(e => e.Name == options.Encoder)
                            : _displayService.SelectEncodingMethod();

                        // Create encryption instance
                        var encoder = _configService.GetEncoder(encoderMetadata.Name);
                        encryption = _algorithmRegistry.CreateAlgorithm(algorithm.Name, encoder);
                    }
                }
                else
                {
                    // Couldn't detect algorithm, ask user
                    Console.WriteLine("Could not detect encryption algorithm from file. Please select manually.");

                    var algorithm = options.Algorithm != null
                        ? _configService.GetAlgorithmMetadata(options.Algorithm)
                        : _displayService.SelectEncryptionAlgorithm();

                    var encoderMetadata = options.Encoder != null
                        ? _configService.GetAllEncoders().First(e => e.Name == options.Encoder)
                        : _displayService.SelectEncodingMethod();

                    // Create encryption instance
                    var encoder = _configService.GetEncoder(encoderMetadata.Name);
                    encryption = _algorithmRegistry.CreateAlgorithm(algorithm.Name, encoder);
                }
            }

            // Process based on mode
            if ( isEncrypting )
            {
                await HandleFileEncryption(options, encryption);
            }
            else // Decrypt
            {
                await HandleFileDecryption(options, encryption);
            }
        }
        catch ( Exception ex )
        {
            // Log at debug level for internal details
            _logger.LogDebug(ex, "File operation failed (details)");

            // User-friendly message at info level
            _logger.LogInformation("File operation failed: {Message}", ex.Message);

            if ( !options.Silent )
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\nOperation failed: {ex.Message}");
                Console.ResetColor();
            }
        }
    }


    private async Task ProcessBatchFile(string batchFile)
    {
        try
        {
            _logger.LogInformation("Processing batch file: {FilePath}", batchFile);

            string jsonContent = await File.ReadAllTextAsync(batchFile);
            var operations = JsonSerializer.Deserialize<List<BatchOperation>>(
                jsonContent,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    ReadCommentHandling = JsonCommentHandling.Skip
                }
            );

            if ( operations == null || operations.Count == 0 )
            {
                _logger.LogWarning("Batch file contains no operations or has invalid format");
                throw new JsonException("Invalid or empty batch file format");
            }

            int totalOperations = operations.Count;
            int successful = 0;
            int failed = 0;

            _logger.LogInformation("Starting batch processing of {Count} operations", totalOperations);

            for ( int i = 0; i < totalOperations; i++ )
            {
                var operation = operations[i];
                _logger.LogInformation("Processing batch operation {Current}/{Total}: {Mode} {Type}",
                    i + 1, totalOperations,
                    operation.Mode,
                    !string.IsNullOrEmpty(operation.InputFile) ? "file" : "text");

                var cliOptions = ConvertBatchOperationToCliOptions(operation);

                try
                {
                    await ProcessSingleOperation(cliOptions);
                    successful++;
                    _logger.LogInformation("Batch operation {Current}/{Total} completed successfully",
                        i + 1, totalOperations);
                }
                catch ( Exception ex )
                {
                    failed++;
                    _logger.LogError(ex, "Batch operation {Current}/{Total} failed: {Mode}",
                        i + 1, totalOperations, operation.Mode);

                    if ( !cliOptions.Silent )
                    {
                        // Only rethrow if this is the only operation or if all have failed
                        if ( totalOperations == 1 || (i == totalOperations - 1 && successful == 0) )
                        {
                            throw;
                        }

                        // Otherwise continue with the next operation
                        Console.WriteLine($"Operation {i + 1} failed: {ex.Message}");
                        Console.WriteLine("Continuing with next operation...");
                    }
                }
            }

            // Final summary
            _logger.LogInformation("Batch processing completed. Summary: {Successful} successful, {Failed} failed out of {Total} operations",
                successful, failed, totalOperations);

            if ( !operations[0].Silent && totalOperations > 1 )
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\nBatch processing summary:");
                Console.ResetColor();
                Console.WriteLine($"- Total operations: {totalOperations}");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"- Successful: {successful}");
                Console.ResetColor();

                if ( failed > 0 )
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"- Failed: {failed}");
                    Console.ResetColor();
                }
            }
        }
        catch ( FileNotFoundException )
        {
            _logger.LogError("Batch file not found: {FilePath}", batchFile);
            throw;
        }
        catch ( JsonException ex )
        {
            _logger.LogError(ex, "Invalid batch file format: {FilePath}", batchFile);
            throw new JsonException($"Invalid batch file format: {ex.Message}", ex);
        }
        catch ( Exception ex )
        {
            _logger.LogError(ex, "Batch processing failed");
            throw;
        }
    }


    private static CliOptions ConvertBatchOperationToCliOptions(BatchOperation operation)
    {
        return new CliOptions
        {
            // Basic operation parameters
            Mode = operation.Mode,
            Algorithm = operation.Algorithm,
            Encoder = operation.Encoder,

            // Text-based encryption/decryption parameters
            Title = operation.Title,
            Instructions = operation.Instructions,
            Token = operation.Token,
            Key = operation.Key,

            // File operation parameters
            InputFile = operation.InputFile,
            OutputFile = operation.OutputFile,
            SaveKeyToFile = operation.SaveKeyToFile,
            KeyFile = operation.KeyFile,

            // Set input type based on whether we have an input file
            InputType = !string.IsNullOrEmpty(operation.InputFile) ? "file" : "text",

            // Other options
            Silent = operation.Silent,
            IsInteractiveMode = false
        };
    }
    private async Task HandleFileEncryption(CliOptions options, IEncryption encryption)
    {
        // Key preparation
        byte[]? key = null;
        if ( !string.IsNullOrEmpty(options.Key) )
        {
            try
            {
                key = Convert.FromBase64String(options.Key);
            }
            catch ( FormatException )
            {
                throw new ArgumentException("The provided key is not valid Base64.");
            }
        }

        // Handle key output
        string? keyOutputPath = null;
        if ( options.SaveKeyToFile )
        {
            keyOutputPath = options.KeyFile ?? Path.ChangeExtension(options.OutputFile, ".key");
        }

        // Encrypt the file with progress indicator
        byte[] usedKey = await Util.ExecuteWithDelayedSpinner(() =>
        {
            return _fileEncryptionService.EncryptFileAsync(
                options.InputFile!,
                options.OutputFile!,
                encryption,
                key,
                keyOutputPath);
        }, "Encrypting file...");

        // Display results if not silent
        if ( !options.Silent )
        {
            DisplayService.DisplayEncryptionResults(options.OutputFile!, usedKey, options.SaveKeyToFile, keyOutputPath);
        }
    }

    private async Task HandleFileDecryption(CliOptions options, IEncryption encryption)
    {
        // Key preparation
        byte[] key;
        if ( !string.IsNullOrEmpty(options.Key) )
        {
            try
            {
                key = Convert.FromBase64String(options.Key);
            }
            catch ( FormatException )
            {
                throw new ArgumentException("The provided key is not valid Base64.");
            }
        }
        else if ( !string.IsNullOrEmpty(options.KeyFile) )
        {
            key = await _fileEncryptionService.LoadKeyFromFileAsync(options.KeyFile);
        }
        else
        {
            key = _displayService.PromptForDecryptionKey();
        }

        try
        {
            // Decrypt the file with progress indicator
            bool success = await Util.ExecuteWithDelayedSpinner(() =>
            {
                return _fileEncryptionService.DecryptFileAsync(
                    options.InputFile!,
                    options.OutputFile!,
                    encryption,
                    key);
            }, "Decrypting file...");

            // Display results if not silent
            if ( !options.Silent )
            {
                DisplayService.DisplayDecryptionResults(success, options.OutputFile!);
            }

            if ( !success )
            {
                // Don't throw CryptographicException - this prevents cascading errors
                _logger.LogError("Decryption failed. The key may be incorrect or the file may be corrupted.");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\nDecryption failed. The key may be incorrect or the file may be corrupted.");
                Console.ResetColor();

                // Return early rather than throwing
                return;
            }
        }
        catch ( Exception ex )
        {
            // Log the exception at DEBUG level only to hide implementation details
            _logger.LogDebug(ex, "Decryption error details");

            // Show user-friendly message
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\nDecryption failed. The key may be incorrect or the file may be corrupted.");
            Console.ResetColor();

            // Don't rethrow - prevents cascading errors
            return;
        }
    }

    private async Task PerformEncryptionAsync(CliOptions options)
    {

        if ( options.Algorithm != null && options.Encoder != null )
        {
            var algorithm = _configService.GetAlgorithmMetadata(options.Algorithm);
            var encoderMetadata = _configService.GetAllEncoders()
                .First(e => e.Name == options.Encoder);  // Get EncoderMetadata
            var encoder = _configService.GetEncoder(options.Encoder);  // Get IEncoder instance

            try
            {
                string combinedData = $"{options.Title};{options.Instructions}";

                var result = await Util.ExecuteWithDelayedSpinner(async () =>
                {
                    var (encryptedData, key) = _encryptionService.Encrypt(algorithm.Name, combinedData);
                    string encodedToken = _encryptionService.EncodeData(encryptedData, options.Encoder);
                    return (encryptedData, key, encodedToken);
                }, "Encrypting data...");

                var (encryptedData, key, encodedToken) = result;

                if ( !options.Silent )
                {
                    DisplayService.DisplayResults(
                        encodedToken,
                        key,
                        algorithm,
                        encoderMetadata, 
                        Encoding.UTF8.GetByteCount(combinedData),
                        encryptedData.Length
                    );
                }

                if ( options.OutputFile != null )
                {
                    await _fileService.SaveTokenAsync(
                        encodedToken,
                        Convert.ToBase64String(key),
                        algorithm.Name,
                        encoderMetadata.Name
                    );
                }
            }
            catch ( Exception ex )
            {
                _logger.LogError(ex, "Encryption failed");
                if ( !options.Silent ) throw;
            }
        }
        else
        {
            // Interactive mode
            var selectedAlgorithm = _displayService.SelectEncryptionAlgorithm();
            var selectedEncoding = _displayService.SelectEncodingMethod();

            var (title, instructions) = DisplayService.GetUserInput();

            try
            {
                string combinedData = $"{title};{instructions}";

                var result = await Util.ExecuteWithDelayedSpinner(async () =>
                {
                    var (encryptedData, key) = _encryptionService.Encrypt(selectedAlgorithm.Name, combinedData);
                    string encodedToken = _encryptionService.EncodeData(encryptedData, selectedEncoding.Name);
                    return (encryptedData, key, encodedToken);
                }, "Encrypting data");

                var (encryptedData, key, encodedToken) = result;

                DisplayService.DisplayResults(
                    encodedToken,
                    key,
                    selectedAlgorithm,
                    selectedEncoding,  
                    Encoding.UTF8.GetByteCount(combinedData),
                    encryptedData.Length
                );

                await _fileService.SaveTokenAsync(
                    encodedToken,
                    Convert.ToBase64String(key),
                    selectedAlgorithm.Name,
                    selectedEncoding.Name
                );
            }
            catch ( Exception ex )
            {
                _logger.LogError(ex, "Encryption failed");
                throw;
            }
        }
    }


    private async Task PerformDecryptionAsync(CliOptions options)
    {
        if ( options.Algorithm != null && options.Encoder != null && options.Token != null && options.Key != null )
        {
            var encoderMetadata = _configService.GetAllEncoders()
                .First(e => e.Name == options.Encoder);

            try
            {
                byte[] key = Convert.FromBase64String(options.Key);
                string token = options.Token;
                string algorithm = options.Algorithm;

                var decryptedText = await Util.ExecuteWithDelayedSpinner(async () =>
                {
                    byte[] encryptedData = _encryptionService.DecodeData(token, options.Encoder);
                    return _encryptionService.Decrypt(algorithm, encryptedData, key);
                }, "Decrypting data");

                if ( !options.Silent )
                {
                    DisplayService.DisplayDecryptedData(Encoding.UTF8.GetBytes(decryptedText));
                }

                if ( options.OutputFile != null )
                {
                    await File.WriteAllTextAsync(options.OutputFile, decryptedText);
                }
            }
            catch ( Exception ex )
            {
                _logger.LogError(ex, "Decryption failed");
                if ( !options.Silent ) throw;
            }
        }
        else
        {
            // Interactive mode
            var selectedAlgorithm = _displayService.SelectEncryptionAlgorithm();
            var selectedEncoding = _displayService.SelectEncodingMethod();

            try
            {
                Console.WriteLine("\nPaste the encoded token:");
                string encodedToken = Console.ReadLine() ?? throw new ArgumentNullException("Token cannot be null");

                Console.WriteLine("\nPaste the decryption key (Base64):");
                string keyBase64 = Console.ReadLine() ?? throw new ArgumentNullException("Key cannot be null");
                byte[] key = Convert.FromBase64String(keyBase64);

                var decryptedText = await Util.ExecuteWithDelayedSpinner(async () =>
                {
                    byte[] encryptedData = _encryptionService.DecodeData(encodedToken, selectedEncoding.Name);
                    return _encryptionService.Decrypt(selectedAlgorithm.Name, encryptedData, key);
                }, "Decrypting data");

                DisplayService.DisplayDecryptedData(Encoding.UTF8.GetBytes(decryptedText));
            }
            catch ( Exception ex )
            {
                _logger.LogError(ex, "Decryption failed");
                throw;
            }
        }
    }

    private static void ShowVersion()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version;
        Graphic.DisplayGraphicAndVersion(version?.ToString() ?? "1.0.0");
    }
}
