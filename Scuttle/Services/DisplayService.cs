using System.Text;
using Scuttle.Models;


namespace Scuttle.Services
{
    internal class DisplayService
    {
        private readonly ConfigurationService _configService;
        private readonly string _appVersion;

        public DisplayService(ConfigurationService configService)
        {
            _configService = configService;
            _appVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0";
        }

        public void DisplayWelcomeBanner()
        {
            Models.Art.Graphic.DisplayGraphicAndVersion(_appVersion);
        }

        public string SelectOperationMode()
        {
            string[] options = new string[]
            {
                "Encrypt (Create new token)",
                "Decrypt (Read existing token)"
            };

            int selected = GetMenuSelection(options, "Select operation mode:");

            // Convert selection to mode string
            return selected == 0 ? "encrypt" : "decrypt";
        }

        public void DisplayEncryptionMethods()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\nSelect encryption method:");
            Console.ResetColor();

            var algorithms = _configService.GetAllAlgorithms().ToList();
            for ( int i = 0; i < algorithms.Count; i++ )
            {
                var algorithm = algorithms[i];
                string legacy = algorithm.IsLegacy ? " (Legacy)" : "";

                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"{i + 1}. ");
                Console.ForegroundColor = algorithm.IsLegacy ? ConsoleColor.Red : ConsoleColor.Green;
                Console.WriteLine($"{algorithm.DisplayName}{legacy}");
                Console.ResetColor();

                if ( !string.IsNullOrEmpty(algorithm.Description) )
                {
                    Console.WriteLine($"   {algorithm.Description}");
                }
            }
        }

        public void DisplayEncodingMethods()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\nSelect encoding method:");
            Console.ResetColor();

            var methods = _configService.GetAllEncoders().ToList();
            for ( int i = 0; i < methods.Count; i++ )
            {
                var method = methods[i];

                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"{i + 1}. ");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"{method.DisplayName}");
                Console.ResetColor();
                Console.WriteLine($" ({method.Description})");
            }
        }

        public void DisplayResults(string encodedToken, byte[] key, AlgorithmMetadata algorithm,
                    EncoderMetadata encoding, int originalLength, int encryptedLength)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\nEncoded Token ({algorithm.DisplayName}, {encoding.DisplayName}):");
            Console.ResetColor();

            if ( encoding.Name == "Base65536" )
            {
                Console.WriteLine("Note: Base65536 encoding uses Unicode characters that may not display correctly in all environments.");
                Console.WriteLine("Token length: " + encodedToken.Length + " characters");
                Console.WriteLine("Base64 equivalent: " + Convert.ToBase64String(Encoding.UTF8.GetBytes(encodedToken)));
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(encodedToken);
                Console.ResetColor();
            }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\nKey (save this for decryption):");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(Convert.ToBase64String(key));
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("\nToken Statistics:");
            Console.ResetColor();
            Console.WriteLine($"Original data length: {originalLength} bytes");
            Console.WriteLine($"Encrypted data length: {encryptedLength} bytes");
            Console.WriteLine($"Encoded token length: {encodedToken.Length} characters");
            Console.WriteLine($"URL-safe: {(IsUrlSafe(encodedToken) ? "Yes" : "No")}");
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

            // Create options array with descriptive text
            string[] options = new string[algorithms.Count];
            for ( int i = 0; i < algorithms.Count; i++ )
            {
                var algorithm = algorithms[i];
                string legacy = algorithm.IsLegacy ? " (Legacy)" : "";
                options[i] = $"{algorithm.DisplayName}{legacy}";

                if ( !string.IsNullOrEmpty(algorithm.Description) )
                {
                    options[i] += $"\n   {algorithm.Description}";
                }
            }

            // Use GetMenuSelection directly without displaying methods first
            int selected = GetMenuSelection(options, "Select encryption method:");
            return algorithms[selected];
        }

        public EncoderMetadata SelectEncodingMethod()
        {
            var methods = _configService.GetAllEncoders().ToList();

            // Create options array with descriptive text
            string[] options = methods.Select(m => $"{m.DisplayName}\n   {m.Description}").ToArray();

            // Use GetMenuSelection directly without displaying methods first
            int selected = GetMenuSelection(options, "Select encoding method:");
            return methods[selected];
        }

        public (string title, string instructions) GetUserInput()
        {
            Console.WriteLine("\nProvide the following inputs to generate a token:");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Title: ");
            Console.ResetColor();
            string title = Console.ReadLine() ?? throw new ArgumentNullException(nameof(title));

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Instructions: ");
            Console.ResetColor();
            string instructions = Console.ReadLine() ?? throw new ArgumentNullException(nameof(instructions));

            return (title, instructions);
        }

        public int GetMenuSelection(string[] options, string prompt = "Select an option:")
        {
            const int startX = 2;
            int startY = Console.CursorTop;

            int currentSelection = 0;

            // Calculate how many lines each option will take
            int[] optionLineCount = options.Select(o => o.Split('\n').Length).ToArray();

            // Calculate total height needed
            int totalHeight = optionLineCount.Sum() + 1; // +1 for prompt

            ConsoleKey key;
            Console.CursorVisible = false;

            do
            {
                // Clear any existing menu display
                for ( int i = 0; i < totalHeight + 2; i++ )
                {
                    Console.SetCursorPosition(0, startY + i);
                    Console.Write(new string(' ', Console.WindowWidth - 1));
                }

                Console.SetCursorPosition(0, startY);
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(prompt);
                Console.ResetColor();

                // Keep track of current Y position
                int currentY = startY + 1;

                for ( int i = 0; i < options.Length; i++ )
                {
                    string[] lines = options[i].Split('\n');

                    // First line with selection highlighting
                    Console.SetCursorPosition(startX, currentY);
                    if ( i == currentSelection )
                    {
                        Console.ForegroundColor = ConsoleColor.Black;
                        Console.BackgroundColor = ConsoleColor.White;
                        Console.Write($" ► {lines[0]} ");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.Write($"   {lines[0]} ");
                        Console.ResetColor();
                    }

                    currentY++;

                    // Additional description lines - never highlighted, but indented
                    for ( int j = 1; j < lines.Length; j++ )
                    {
                        Console.SetCursorPosition(startX + 3, currentY);
                        Console.ForegroundColor = ConsoleColor.Gray;
                        Console.Write(lines[j]);
                        Console.ResetColor();
                        currentY++;
                    }
                }

                key = Console.ReadKey(true).Key;

                if ( key == ConsoleKey.DownArrow && currentSelection < options.Length - 1 )
                {
                    currentSelection++;
                }
                else if ( key == ConsoleKey.UpArrow && currentSelection > 0 )
                {
                    currentSelection--;
                }
            } while ( key != ConsoleKey.Enter );

            // Clean up after selection
            for ( int i = 0; i < totalHeight + 2; i++ )
            {
                Console.SetCursorPosition(0, startY + i);
                Console.Write(new string(' ', Console.WindowWidth - 1));
            }

            Console.SetCursorPosition(0, startY);
            // Only display the first line of the selected option in the final result
            string selectedOption = options[currentSelection].Split('\n')[0];
            Console.WriteLine($"{prompt} {selectedOption}");

            Console.CursorVisible = true;
            return currentSelection;
        }
        public bool YesNoPrompt(string promptText = "Would you like to perform another operation?")
        {
            string[] options = new string[] { "Yes", "No" };
            int selected = GetMenuSelection(options, promptText);
            return selected == 0; // Yes is index 0
        }
        private static bool IsUrlSafe(string input)
            => Uri.EscapeDataString(input) == input;
    }
}
