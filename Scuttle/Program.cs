using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Scuttle.Models;
using Scuttle.Services;

class Program
{
    private readonly ConfigurationService _configService;
    private readonly EncryptionService _encryptionService;
    private readonly FileService _fileService;
    private readonly DisplayService _displayService;
    private readonly ILogger<Program> _logger;
    private readonly ArgumentParser _parser;
    private readonly OutputFormatter _formatter;

    public Program(
        IConfiguration configuration,
        ILogger<Program> logger,
        ArgumentParser parser,
        OutputFormatter formatter)
    {
        _configService = new ConfigurationService(configuration);
        _encryptionService = new EncryptionService(_configService);
        _fileService = new FileService();
        _displayService = new DisplayService(_configService);
        _logger = logger;
        _parser = parser;
        _formatter = formatter;
    }

    public static async Task Main(string[] args)
    {
        // Setup configuration
        var config = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();

        // Setup logging with configuration
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder
                .AddConfiguration(config.GetSection("Logging")) 
                .AddFilter("Microsoft", LogLevel.Warning)
                .AddFilter("System", LogLevel.Warning)
                .AddFilter("Scuttle", LogLevel.Information)
                .AddConsole();
        });

        var logger = loggerFactory.CreateLogger<Program>();
        var parserLogger = loggerFactory.CreateLogger<ArgumentParser>();
        var parser = new ArgumentParser(config, parserLogger);
        var formatter = new OutputFormatter();

        try
        {
            var program = new Program(config, logger, parser, formatter);
            await program.RunAsync(args);
        }
        catch ( Exception ex )
        {
            logger.LogError(ex, "Application failed");
            Environment.Exit(1);
        }
    }

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

            // Handle special commands first
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
        bool continueProgram = true;
        while ( continueProgram )
        {
            try
            {
                _displayService.DisplayMainMenu();
                var mode = _displayService.GetOperationMode();

                var options = new CliOptions
                {
                    Mode = mode,
                    IsInteractiveMode = true
                };

                await ProcessSingleOperation(options);
            }
            catch ( Exception ex )
            {
                _logger.LogError(ex, "Operation failed");
                Console.WriteLine($"\nAn error occurred: {ex.Message}");
            }

            continueProgram = _displayService.PromptContinue();
            if ( continueProgram )
            {
                Console.Clear();
            }
        }

        Console.WriteLine("\nThank you for using the Token Generator. Press any key to exit.");
        Console.ReadKey();
    }

    private async Task ProcessSingleOperation(CliOptions options)
    {
        try
        {
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

    private async Task ProcessBatchFile(string batchFile)
    {
        try
        {
            var operations = JsonSerializer.Deserialize<List<BatchOperation>>(
                await File.ReadAllTextAsync(batchFile)
            );

            if ( operations == null )
            {
                throw new JsonException("Invalid batch file format");
            }

            foreach ( var operation in operations )
            {
                _logger.LogInformation("Processing batch operation: {Mode}", operation.Mode);
                var cliOptions = ConvertBatchOperationToCliOptions(operation);

                try
                {
                    await ProcessSingleOperation(cliOptions);
                }
                catch ( Exception ex )
                {
                    _logger.LogError(ex, "Batch operation failed: {Mode}", operation.Mode);
                    if ( !cliOptions.Silent )
                    {
                        throw;
                    }
                }
            }
        }
        catch ( Exception ex )
        {
            _logger.LogError(ex, "Batch processing failed");
            throw;
        }
    }

    private CliOptions ConvertBatchOperationToCliOptions(BatchOperation operation)
    {
        return new CliOptions
        {
            Mode = operation.Mode,
            Algorithm = operation.Algorithm,
            Encoder = operation.Encoder,
            Title = operation.Title,
            Instructions = operation.Instructions,
            Token = operation.Token,
            Key = operation.Key,
            OutputFile = operation.OutputFile,
            Silent = false, 
            IsInteractiveMode = false  
        };
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
                var (encryptedData, key) = _encryptionService.Encrypt(algorithm.Name, combinedData);
                string encodedToken = _encryptionService.EncodeData(encryptedData, options.Encoder);

                if ( !options.Silent )
                {
                    _displayService.DisplayResults(
                        encodedToken,
                        key,
                        algorithm,
                        encoderMetadata,  // Use EncoderMetadata instead of IEncoder
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
                        encoderMetadata.Name  // Use EncoderMetadata.Name
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
            _displayService.DisplayEncryptionMethods();
            var selectedAlgorithm = _displayService.SelectEncryptionAlgorithm();

            _displayService.DisplayEncodingMethods();
            var selectedEncoding = _displayService.SelectEncodingMethod();

            var (title, instructions) = _displayService.GetUserInput();

            try
            {
                string combinedData = $"{title};{instructions}";
                var (encryptedData, key) = _encryptionService.Encrypt(selectedAlgorithm.Name, combinedData);
                string encodedToken = _encryptionService.EncodeData(encryptedData, selectedEncoding.Name);

                _displayService.DisplayResults(
                    encodedToken,
                    key,
                    selectedAlgorithm,
                    selectedEncoding,  // Already EncoderMetadata
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
                byte[] encryptedData = _encryptionService.DecodeData(options.Token, options.Encoder);
                string decryptedText = _encryptionService.Decrypt(options.Algorithm, encryptedData, key);

                if ( !options.Silent )
                {
                    _displayService.DisplayDecryptedData(Encoding.UTF8.GetBytes(decryptedText));
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
            _displayService.DisplayEncryptionMethods();
            var selectedAlgorithm = _displayService.SelectEncryptionAlgorithm();

            _displayService.DisplayEncodingMethods();
            var selectedEncoding = _displayService.SelectEncodingMethod();

            try
            {
                Console.WriteLine("\nPaste the encoded token:");
                string encodedToken = Console.ReadLine() ?? throw new ArgumentNullException("Token cannot be null");

                Console.WriteLine("\nPaste the decryption key (Base64):");
                string keyBase64 = Console.ReadLine() ?? throw new ArgumentNullException("Key cannot be null");
                byte[] key = Convert.FromBase64String(keyBase64);

                byte[] encryptedData = _encryptionService.DecodeData(encodedToken, selectedEncoding.Name);
                string decryptedText = _encryptionService.Decrypt(selectedAlgorithm.Name, encryptedData, key);

                _displayService.DisplayDecryptedData(Encoding.UTF8.GetBytes(decryptedText));
                await Task.CompletedTask;
            }
            catch ( Exception ex )
            {
                _logger.LogError(ex, "Decryption failed");
                throw;
            }
        }
    }

    private void ShowVersion()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version;
        Console.WriteLine($"Token Generator v{version}");
    }
}
