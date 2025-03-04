using System.Text;
using Token_Generator.Models.Token_Generator.Models;
using Token_Generator.Models;

namespace Token_Generator.Services
{
    internal class DisplayService
    {
        private readonly ConfigurationService _configService;

        public DisplayService(ConfigurationService configService)
        {
            _configService = configService;
        }

        public void DisplayMainMenu()
        {
            Console.WriteLine("\nSelect operation mode:");
            Console.WriteLine("1. Encrypt (Create new token)");
            Console.WriteLine("2. Decrypt (Read existing token)");
        }

        public void DisplayEncryptionMethods()
        {
            Console.WriteLine("\nSelect encryption method:");
            var algorithms = _configService.GetAllAlgorithms().ToList();
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

        public void DisplayEncodingMethods()
        {
            Console.WriteLine("\nSelect encoding method:");
            var methods = _configService.GetAllEncoders().ToList();
            for ( int i = 0; i < methods.Count; i++ )
            {
                var method = methods[i];
                Console.WriteLine($"{i + 1}. {method.DisplayName} ({method.Description})");
            }
        }

        public void DisplayResults(string encodedToken, byte[] key, AlgorithmMetadata algorithm,
            EncoderMetadata encoding, int originalLength, int encryptedLength)
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

        public void DisplayDecryptedData(byte[] decryptedData)
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

        public AlgorithmMetadata SelectEncryptionAlgorithm()
        {
            var algorithms = _configService.GetAllAlgorithms().ToList();
            if ( int.TryParse(Console.ReadLine(), out int choice) && choice > 0 && choice <= algorithms.Count )
            {
                return algorithms[choice - 1];
            }
            return algorithms[0]; // Default to first algorithm
        }

        public EncoderMetadata SelectEncodingMethod()
        {
            var methods = _configService.GetAllEncoders().ToList();
            if ( int.TryParse(Console.ReadLine(), out int choice) && choice > 0 && choice <= methods.Count )
            {
                return methods[choice - 1];
            }
            return methods[0]; // Default to first method
        }

        public (string title, string instructions) GetUserInput()
        {
            Console.WriteLine("\nProvide the following inputs to generate a token:");
            Console.WriteLine("Title: ");
            string title = Console.ReadLine() ?? throw new ArgumentNullException(nameof(title));

            Console.WriteLine("Instructions: ");
            string instructions = Console.ReadLine() ?? throw new ArgumentNullException(nameof(instructions));

            return (title, instructions);
        }

        public string GetOperationMode()
        {
            string? input = Console.ReadLine();
            // Convert numeric input to actual mode
            return input switch
            {
                "1" => "encrypt",
                "2" => "decrypt",
                "decrypt" => "decrypt",
                "encrypt" => "encrypt",
                "en" => "encrypt",
                "de" => "decrypt",
                _ => "encrypt" 
            };
        }
        //test
        public bool PromptContinue()
        {
            Console.WriteLine("\nWould you like to perform another operation? (y/n)");
            string? response = Console.ReadLine()?.ToLower();
            return response == "y" || response == "yes";
        }

        private static bool IsUrlSafe(string input)
            => Uri.EscapeDataString(input) == input;
    }
}
