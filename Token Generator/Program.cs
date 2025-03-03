using Microsoft.Extensions.Configuration;
using System.Text;
using Token_Generator.Models;

class Program
{
    private readonly ConfigurationService _configService;
    private readonly EncryptionService _encryptionService;

    public Program(IConfiguration configuration)
    {
        _configService = new ConfigurationService(configuration);
        _encryptionService = new EncryptionService(_configService);
    }

    public static async Task Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        var config = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();

        var program = new Program(config);
        await program.RunAsync();
    }

    private async Task RunAsync()
    {
        bool continueProgram = true;
        while ( continueProgram )
        {
            try
            {
                DisplayMainMenu();
                var mode = GetOperationMode();

                switch ( mode )
                {
                    case "1":
                        await PerformEncryptionAsync();
                        break;
                    case "2":
                        await PerformDecryptionAsync();
                        break;
                }
            }
            catch ( Exception ex )
            {
                Console.WriteLine($"\nAn error occurred: {ex.Message}");
            }

            continueProgram = PromptContinue();
            if ( continueProgram )
            {
                Console.Clear();
            }
        }

        Console.WriteLine("\nThank you for using the Token Generator. Press any key to exit.");
        Console.ReadKey();
    }

    private void DisplayMainMenu()
    {
        Console.WriteLine("\nSelect operation mode:");
        Console.WriteLine("1. Encrypt (Create new token)");
        Console.WriteLine("2. Decrypt (Read existing token)");
    }

    private string GetOperationMode()
    {
        string? input = Console.ReadLine();
        return input == "2" ? "2" : "1";
    }

    private async Task PerformEncryptionAsync()
    {
        // Display available encryption methods
        DisplayEncryptionMethods();
        var selectedAlgorithm = SelectEncryptionAlgorithm();

        // Display encoding methods
        DisplayEncodingMethods();
        var selectedEncoding = SelectEncodingMethod();

        // Get user input
        var (title, instructions) = GetUserInput();

        try
        {
            // Perform encryption
            string combinedData = $"{title};{instructions}";
            var implementation = _configService.GetImplementation(selectedAlgorithm.Name);

            byte[] key = implementation.GenerateKey();
            byte[] dataBytes = Encoding.UTF8.GetBytes(combinedData);
            byte[] encryptedData = implementation.Encrypt(dataBytes, key);

            // Encode the data
            string encodedToken = _encryptionService.EncodeData(encryptedData, selectedEncoding.Name);

            // Display results
            DisplayResults(encodedToken, key, selectedAlgorithm, selectedEncoding, dataBytes.Length, encryptedData.Length);

            // Offer to save
            await SaveToFileAsync(encodedToken, Convert.ToBase64String(key), selectedAlgorithm.Name, selectedEncoding.Name);
        }
        catch ( Exception ex )
        {
            Console.WriteLine($"\nEncryption failed: {ex.Message}");
        }
    }

    private async Task PerformDecryptionAsync()
    {
        // Display available encryption methods
        DisplayEncryptionMethods();
        var selectedAlgorithm = SelectEncryptionAlgorithm();

        // Display encoding methods
        DisplayEncodingMethods();
        var selectedEncoding = SelectEncodingMethod();

        // Get token and key
        Console.WriteLine("\nPaste the encoded token:");
        string encodedToken = Console.ReadLine() ?? throw new ArgumentNullException(nameof(encodedToken));

        Console.WriteLine("\nPaste the decryption key (Base64):");
        string keyBase64 = Console.ReadLine() ?? throw new ArgumentNullException(nameof(keyBase64));
        byte[] key = Convert.FromBase64String(keyBase64);

        try
        {
            // Decode and decrypt
            byte[] encryptedData = _encryptionService.DecodeData(encodedToken, selectedEncoding.Name);
            var implementation = _configService.GetImplementation(selectedAlgorithm.Name);
            byte[] decryptedData = implementation.Decrypt(encryptedData, key);

            // Parse and display results
            DisplayDecryptedData(decryptedData);
        }
        catch ( Exception ex )
        {
            Console.WriteLine($"\nDecryption failed: {ex.Message}");
        }
    }

    private void DisplayEncryptionMethods()
    {
        Console.WriteLine("\nSelect encryption method:");
        var algorithms = _configService.Algorithms;
        for ( int i = 0; i < algorithms.Count; i++ )
        {
            var algorithm = algorithms[i];
            string legacy = algorithm.IsLegacy ? " (Legacy)" : "";
            Console.WriteLine($"{i + 1}. {algorithm.DisplayName}{legacy}");
            if ( !string.IsNullOrEmpty(algorithm.Description) )
            {
                Console.WriteLine($"   {algorithm.Description}");
            }
        }
    }

    private void DisplayEncodingMethods()
    {
        Console.WriteLine("\nSelect encoding method:");
        var methods = _configService.EncodingMethods;
        for ( int i = 0; i < methods.Count; i++ )
        {
            var method = methods[i];
            Console.WriteLine($"{i + 1}. {method.DisplayName} ({method.Description})");
        }
    }

    private EncryptionAlgorithm SelectEncryptionAlgorithm()
    {
        var algorithms = _configService.Algorithms;
        if ( int.TryParse(Console.ReadLine(), out int choice) && choice > 0 && choice <= algorithms.Count )
        {
            return algorithms[choice - 1];
        }
        return algorithms[0]; // Default to first algorithm
    }

    private EncodingMethod SelectEncodingMethod()
    {
        var methods = _configService.EncodingMethods;
        if ( int.TryParse(Console.ReadLine(), out int choice) && choice > 0 && choice <= methods.Count )
        {
            return methods[choice - 1];
        }
        return methods[0]; // Default to first method
    }

    private (string title, string instructions) GetUserInput()
    {
        Console.WriteLine("\nProvide the following inputs to generate a token:");
        Console.WriteLine("Title: ");
        string title = Console.ReadLine() ?? throw new ArgumentNullException(nameof(title));

        Console.WriteLine("Instructions: ");
        string instructions = Console.ReadLine() ?? throw new ArgumentNullException(nameof(instructions));

        return (title, instructions);
    }

    private void DisplayResults(string encodedToken, byte[] key, EncryptionAlgorithm algorithm,
        EncodingMethod encoding, int originalLength, int encryptedLength)
    {
        Console.WriteLine($"\nEncoded Token ({algorithm.DisplayName}, {encoding.DisplayName}):");

        if ( encoding.Name == "Base65536" )
        {
            Console.WriteLine("Note: Base65536 encoding uses Unicode characters that may not display correctly in all environments.");
            Console.WriteLine("Token length: " + encodedToken.Length + " characters");
            Console.WriteLine("Base64 equivalent: " + Convert.ToBase64String(Encoding.UTF8.GetBytes(encodedToken)));
        }
        else
        {
            Console.WriteLine(encodedToken);
        }

        Console.WriteLine($"\nKey (save this for decryption): {Convert.ToBase64String(key)}");

        Console.WriteLine("\nToken Statistics:");
        Console.WriteLine($"Original data length: {originalLength} bytes");
        Console.WriteLine($"Encrypted data length: {encryptedLength} bytes");
        Console.WriteLine($"Encoded token length: {encodedToken.Length} characters");
        Console.WriteLine($"URL-safe: {IsUrlSafe(encodedToken)}");
    }

    private void DisplayDecryptedData(byte[] decryptedData)
    {
        string decryptedText = Encoding.UTF8.GetString(decryptedData);
        string[] parts = decryptedText.Split(';');

        if ( parts.Length >= 2 )
        {
            Console.WriteLine("\nDecrypted Data:");
            Console.WriteLine($"Title: {parts[0]}");
            Console.WriteLine($"Instructions: {parts[1]}");
        }
        else
        {
            Console.WriteLine("\nDecrypted Data (raw):");
            Console.WriteLine(decryptedText);
        }
    }

    private async Task SaveToFileAsync(string token, string key, string encMethod, string encodeMethod)
    {
        if ( !PromptSaveToFile() ) return;

        string? filePath = GetFilePath();
        if ( string.IsNullOrEmpty(filePath) ) return;

        try
        {
            await SaveContentToFileAsync(filePath, token, key, encMethod, encodeMethod);
        }
        catch ( Exception ex )
        {
            Console.WriteLine($"\nError saving file: {ex.Message}");
        }
    }

    private static bool PromptSaveToFile()
    {
        Console.WriteLine("\nWould you like to save the token and key to a file? (y/n)");
        string? response = Console.ReadLine()?.ToLower();
        return response == "y" || response == "yes";
    }

    private static string? GetFilePath()
    {
        Console.WriteLine("\nEnter the file path and name (e.g., C:\\Tokens\\mytoken.txt):");
        return Console.ReadLine();
    }

    private static async Task SaveContentToFileAsync(string filePath, string token, string key,
        string encMethod, string encodeMethod)
    {
        string? directory = Path.GetDirectoryName(filePath);
        if ( !string.IsNullOrEmpty(directory) )
        {
            Directory.CreateDirectory(directory);
        }

        var content = new StringBuilder()
            .AppendLine("Token Generator Output")
            .AppendLine("--------------------")
            .AppendLine($"Generated: {DateTime.Now}")
            .AppendLine($"Encryption Method: {encMethod}")
            .AppendLine($"Encoding Method: {encodeMethod}")
            .AppendLine("\nTOKEN:")
            .AppendLine(token)
            .AppendLine("\nKEY (Base64):")
            .AppendLine(key)
            .AppendLine("\nNote: Keep this file secure. The key is required to decrypt the token.");

        await File.WriteAllTextAsync(filePath, content.ToString());
        Console.WriteLine($"\nFile saved successfully to: {filePath}");
    }

    private static bool PromptContinue()
    {
        Console.WriteLine("\nWould you like to perform another operation? (y/n)");
        string? response = Console.ReadLine()?.ToLower();
        return response == "y" || response == "yes";
    }

    private static bool IsUrlSafe(string input)
        => Uri.EscapeDataString(input) == input;
}
