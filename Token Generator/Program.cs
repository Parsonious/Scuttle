using Microsoft.Extensions.Configuration;
using System.Text;
using Token_Generator.Services;

class Program
{
    private readonly ConfigurationService _configService;
    private readonly EncryptionService _encryptionService;
    private readonly FileService _fileService;
    private readonly DisplayService _displayService;

    public Program(IConfiguration configuration)
    {
        _configService = new ConfigurationService(configuration);
        _encryptionService = new EncryptionService(_configService);
        _fileService = new FileService();
        _displayService = new DisplayService(_configService);
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
                _displayService.DisplayMainMenu();
                var mode = _displayService.GetOperationMode();

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

            continueProgram = _displayService.PromptContinue();
            if ( continueProgram )
            {
                Console.Clear();
            }
        }

        Console.WriteLine("\nThank you for using the Token Generator. Press any key to exit.");
        Console.ReadKey();
    }

    private async Task PerformEncryptionAsync()
    {
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
            Console.WriteLine($"\nEncryption failed: {ex.Message}");
        }
    }

    private async Task PerformDecryptionAsync()
    {
        _displayService.DisplayEncryptionMethods();
        var selectedAlgorithm = _displayService.SelectEncryptionAlgorithm();

        _displayService.DisplayEncodingMethods();
        var selectedEncoding = _displayService.SelectEncodingMethod();

        try
        {
            // Get token and key using DisplayService
            Console.WriteLine("\nPaste the encoded token:");
            string encodedToken = Console.ReadLine() ?? throw new ArgumentNullException("Token cannot be null");

            Console.WriteLine("\nPaste the decryption key (Base64):");
            string keyBase64 = Console.ReadLine() ?? throw new ArgumentNullException("Key cannot be null");
            byte[] key = Convert.FromBase64String(keyBase64);

            // Perform decryption
            byte[] encryptedData = _encryptionService.DecodeData(encodedToken, selectedEncoding.Name);
            string decryptedText = _encryptionService.Decrypt(selectedAlgorithm.Name, encryptedData, key);

            // Display results using DisplayService
            _displayService.DisplayDecryptedData(Encoding.UTF8.GetBytes(decryptedText));
        }
        catch ( Exception ex )
        {
            Console.WriteLine($"\nDecryption failed: {ex.Message}");
        }
    }
}
