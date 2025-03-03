using Microsoft.Extensions.Configuration;
using System.Text;
using Token_Generator.Encoders;
using Token_Generator.Encrypt;

class Program
{
    enum OperationMode
    {
        Encrypt,
        Decrypt
    }
    enum EncryptionMethod
    {
        AES_GCM,
        Base65536,
        XChaCha20,
        ChaCha20,
        ThreeFish
    }

    enum EncodingMethod
    {
        Base64,
        Base85,
        Base65536
    }

    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        var config = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();

        // Initialize encryption methods
        var aesGcm = new AesGcmEncrypt();
        var xChaCha20 = new XChaCha20Encrypt();
        var chaCha20 = new ChaCha20Encrypt();
        var threeFish = new ThreefishEncrypt();

        bool continueProgram = true;
        while ( continueProgram )
        {
            try
            {
                // Ask for operation mode
                Console.WriteLine("\nSelect operation mode:");
                Console.WriteLine("1. Encrypt (Create new token)");
                Console.WriteLine("2. Decrypt (Read existing token)");

                OperationMode mode = OperationMode.Encrypt;
                if ( int.TryParse(Console.ReadLine(), out int modeChoice) )
                {
                    mode = modeChoice switch
                    {
                        2 => OperationMode.Decrypt,
                        _ => OperationMode.Encrypt
                    };
                }

                if ( mode == OperationMode.Encrypt )
                {
                    PerformEncryption(aesGcm, xChaCha20, chaCha20, threeFish);
                }
                else
                {
                    PerformDecryption(aesGcm, xChaCha20, chaCha20, threeFish);
                }
            }
            catch ( Exception ex )
            {
                Console.WriteLine($"\nAn error occurred: {ex.Message}");
            }

            Console.WriteLine("\nWould you like to perform another operation? (y/n)");
            string? response = Console.ReadLine()?.ToLower();
            continueProgram = response == "y" || response == "yes";

            if ( continueProgram )
            {
                Console.Clear();
            }
        }

        Console.WriteLine("\nThank you for using the Token Generator. Press any key to exit.");
        Console.ReadKey();
    }

    private static bool IsUrlSafe(string input)
    {
        return Uri.EscapeDataString(input) == input;
    }
    private static void PerformEncryption(AesGcmEncrypt aesGcm, XChaCha20Encrypt xChaCha20,
        ChaCha20Encrypt chaCha20, ThreefishEncrypt threeFish)
    {
        try
        {
            // Get user input for encryption method
            Console.WriteLine("\nSelect encryption method:");
            Console.WriteLine("1. AES-GCM");
            Console.WriteLine("2. XChaCha20");
            Console.WriteLine("3. ChaCha20");
            Console.WriteLine("4. ThreeFish");

            EncryptionMethod selectedEncryption = EncryptionMethod.AES_GCM; // Default
            if ( int.TryParse(Console.ReadLine(), out int encChoice) )
            {
                selectedEncryption = encChoice switch
                {
                    1 => EncryptionMethod.AES_GCM,
                    2 => EncryptionMethod.XChaCha20,
                    3 => EncryptionMethod.ChaCha20,
                    4 => EncryptionMethod.ThreeFish,
                    _ => EncryptionMethod.AES_GCM
                };
            }

            // Get user input for encoding method
            Console.WriteLine("\nSelect encoding method:");
            Console.WriteLine("1. Base64 (URL-safe, compact)");
            Console.WriteLine("2. Base85 (more compact, not URL-safe)");
            Console.WriteLine("3. Base65536 (most compact, Unicode-based)");

            EncodingMethod selectedMethod = EncodingMethod.Base64;
            if ( int.TryParse(Console.ReadLine(), out int choice) )
            {
                selectedMethod = choice switch
                {
                    1 => EncodingMethod.Base64,
                    2 => EncodingMethod.Base85,
                    3 => EncodingMethod.Base65536,
                    _ => EncodingMethod.Base64
                };
            }

            Console.WriteLine("\nProvide the following inputs to generate a token:");
            Console.WriteLine("Title: ");
            string title = Console.ReadLine() ?? throw new ArgumentNullException(nameof(title), "Article cannot be null.");
            Console.WriteLine("Instructions: ");
            string instructions = Console.ReadLine() ?? throw new ArgumentNullException(nameof(instructions), "Instructions cannot be null.");

            // Generate key based on selected encryption method
            byte[] key = selectedEncryption switch
            {
                EncryptionMethod.AES_GCM => aesGcm.GenerateKey(),
                EncryptionMethod.XChaCha20 => xChaCha20.GenerateKey(),
                EncryptionMethod.ChaCha20 => chaCha20.GenerateKey(),
                EncryptionMethod.ThreeFish => threeFish.GenerateKey(),
                _ => aesGcm.GenerateKey()
            };

            // Combine input data
            string combinedData = $"{title};{instructions}";
            byte[] dataBytes = Encoding.UTF8.GetBytes(combinedData);

            // Encrypt data using selected method
            byte[] encryptedData = selectedEncryption switch
            {
                EncryptionMethod.AES_GCM => aesGcm.Encrypt(dataBytes, key),
                EncryptionMethod.XChaCha20 => xChaCha20.Encrypt(dataBytes, key),
                EncryptionMethod.ChaCha20 => chaCha20.Encrypt(dataBytes, key),
                EncryptionMethod.ThreeFish => threeFish.Encrypt(dataBytes, key),
                _ => aesGcm.Encrypt(dataBytes, key)
            };

            // Encode the encrypted data
            string encodedToken = selectedMethod switch
            {
                EncodingMethod.Base64 => Base64.UrlEncode(encryptedData),
                EncodingMethod.Base85 => Base85.Encode(encryptedData),
                EncodingMethod.Base65536 => Base65536.Encode(encryptedData),
                _ => Base64.UrlEncode(encryptedData)
            };

            Console.WriteLine($"\nEncoded Token ({selectedEncryption}, {selectedMethod}):");
            if ( selectedMethod == EncodingMethod.Base65536 )
            {
                Console.WriteLine("Note: Base65536 encoding uses Unicode characters that may not display correctly in all environments.");
                Console.WriteLine("Token length: " + encodedToken.Length + " characters");
                // Optionally provide alternative display
                Console.WriteLine("Base64 equivalent: " + Convert.ToBase64String(encryptedData));
            }
            else
            {
                Console.WriteLine(encodedToken);
            }
            Console.WriteLine($"\nKey (save this for decryption): {Convert.ToBase64String(key)}");

            // Display token statistics
            Console.WriteLine("\nToken Statistics:");
            Console.WriteLine($"Original data length: {dataBytes.Length} bytes");
            Console.WriteLine($"Encrypted data length: {encryptedData.Length} bytes");
            Console.WriteLine($"Encoded token length: {encodedToken.Length} characters");
            Console.WriteLine($"URL-safe: {IsUrlSafe(encodedToken)}");
            Console.WriteLine();
            
            SaveToFile(encodedToken, Convert.ToBase64String(key), selectedEncryption, selectedMethod);
        }
            catch (Exception ex )
            {
                Console.WriteLine($"\nAn error occurred: {ex.Message}");
            }
    }
    private static void PerformDecryption(AesGcmEncrypt aesGcm, XChaCha20Encrypt xChaCha20,
        ChaCha20Encrypt chaCha20, ThreefishEncrypt threeFish)
    {
        // Get user input for encryption method
        Console.WriteLine("\nSelect the encryption method used:");
        Console.WriteLine("1. AES-GCM");
        Console.WriteLine("2. XChaCha20");
        Console.WriteLine("3. ChaCha20");
        Console.WriteLine("4. ThreeFish");

        EncryptionMethod selectedEncryption = EncryptionMethod.AES_GCM;
        if ( int.TryParse(Console.ReadLine(), out int encChoice) )
        {
            selectedEncryption = encChoice switch
            {
                1 => EncryptionMethod.AES_GCM,
                2 => EncryptionMethod.XChaCha20,
                3 => EncryptionMethod.ChaCha20,
                4 => EncryptionMethod.ThreeFish,
                _ => EncryptionMethod.AES_GCM
            };
        }

        // Get user input for encoding method
        Console.WriteLine("\nSelect the encoding method used:");
        Console.WriteLine("1. Base64 (URL-safe, compact)");
        Console.WriteLine("2. Base85 (more compact, not URL-safe)");
        Console.WriteLine("3. Base65536 (most compact, Unicode-based)");

        EncodingMethod selectedMethod = EncodingMethod.Base64;
        if ( int.TryParse(Console.ReadLine(), out int choice) )
        {
            selectedMethod = choice switch
            {
                1 => EncodingMethod.Base64,
                2 => EncodingMethod.Base85,
                3 => EncodingMethod.Base65536,
                _ => EncodingMethod.Base64
            };
        }

        Console.WriteLine("\nPaste the encoded token:");
        string encodedToken = Console.ReadLine() ?? throw new ArgumentNullException(nameof(encodedToken), "Token cannot be null.");

        Console.WriteLine("\nPaste the decryption key (Base64):");
        string keyBase64 = Console.ReadLine() ?? throw new ArgumentNullException(nameof(keyBase64), "Key cannot be null.");
        byte[] key = Convert.FromBase64String(keyBase64);

        // Decode the token
        byte[] encryptedData = selectedMethod switch
        {
            EncodingMethod.Base64 => Base64.UrlDecode(encodedToken),
            EncodingMethod.Base85 => Base85.Decode(encodedToken),
            EncodingMethod.Base65536 => Base65536.Decode(encodedToken),
            _ => Base64.UrlDecode(encodedToken)
        };

        // Decrypt the data
        byte[] decryptedData = selectedEncryption switch
        {
            EncryptionMethod.AES_GCM => aesGcm.Decrypt(encryptedData, key),
            EncryptionMethod.XChaCha20 => xChaCha20.Decrypt(encryptedData, key),
            EncryptionMethod.ChaCha20 => chaCha20.Decrypt(encryptedData, key),
            EncryptionMethod.ThreeFish => threeFish.Decrypt(encryptedData, key),
            _ => aesGcm.Decrypt(encryptedData, key)
        };

        // Parse the decrypted data
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
    private static void SaveToFile(string token, string key, EncryptionMethod encMethod, EncodingMethod encodeMethod)
    {
        Console.WriteLine("\nWould you like to save the token and key to a file? (y/n)");
        string? response = Console.ReadLine()?.ToLower();

        if ( response == "y" || response == "yes" )
        {
            Console.WriteLine("\nEnter the file path and name (e.g., C:\\Tokens\\mytoken.txt):");
            string? filePath = Console.ReadLine();

            if ( string.IsNullOrEmpty(filePath) )
            {
                Console.WriteLine("Invalid file path. Skipping file save.");
                return;
            }

            try
            {
                // Create directory if it doesn't exist
                string? directory = Path.GetDirectoryName(filePath);
                if ( !string.IsNullOrEmpty(directory) )
                {
                    Directory.CreateDirectory(directory);
                }

                // Prepare the content
                var content = new StringBuilder();
                content.AppendLine("Token Generator Output");
                content.AppendLine("--------------------");
                content.AppendLine($"Generated: {DateTime.Now}");
                content.AppendLine($"Encryption Method: {encMethod}");
                content.AppendLine($"Encoding Method: {encodeMethod}");
                content.AppendLine("\nTOKEN:");
                content.AppendLine(token);
                content.AppendLine("\nKEY (Base64):");
                content.AppendLine(key);
                content.AppendLine("\nNote: Keep this file secure. The key is required to decrypt the token.");

                // Write to file
                File.WriteAllText(filePath, content.ToString());
                Console.WriteLine($"\nFile saved successfully to: {filePath}");
            }
            catch ( Exception ex )
            {
                Console.WriteLine($"\nError saving file: {ex.Message}");
            }
        }
    }

}
