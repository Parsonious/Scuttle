using Microsoft.Extensions.Logging;
using Scuttle.Interfaces;
using System.Security.Cryptography;
using System.Text;

namespace Scuttle.Services
{
    /// <summary>
    /// Service for handling file encryption and decryption operations
    /// </summary>
    public class FileEncryptionService
    {
        private readonly ILogger<FileEncryptionService> _logger;

        public FileEncryptionService(ILogger<FileEncryptionService> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Encrypt a file using the specified algorithm
        /// </summary>
        /// <param name="inputFilePath">Path to the file to encrypt</param>
        /// <param name="outputFilePath">Path where the encrypted file should be saved</param>
        /// <param name="encryption">Encryption algorithm to use</param>
        /// <param name="key">Key to use, or null to generate a new one</param>
        /// <param name="keyOutputPath">Path where the key should be saved, or null if it shouldn't be saved</param>
        /// <returns>The encryption key used</returns>
        public byte[] EncryptFile(string inputFilePath, string outputFilePath, IEncryption encryption, byte[]? key = null, string? keyOutputPath = null)
        {
            if ( !File.Exists(inputFilePath) )
                throw new FileNotFoundException("Input file not found", inputFilePath);

            // Read the file
            _logger.LogInformation("Reading file: {Path}", inputFilePath);
            byte[] fileData = File.ReadAllBytes(inputFilePath);

            // Generate or use the provided key
            key ??= encryption.GenerateKey();

            // Encrypt the data
            _logger.LogInformation("Encrypting file data using {Algorithm}", encryption.GetType().Name);
            byte[] encryptedData = encryption.Encrypt(fileData, key);

            // Save the encrypted data
            _logger.LogInformation("Writing encrypted data to: {Path}", outputFilePath);
            File.WriteAllBytes(outputFilePath, encryptedData);

            // Save the key if requested
            if ( !string.IsNullOrEmpty(keyOutputPath) )
            {
                _logger.LogInformation("Saving encryption key to: {Path}", keyOutputPath);
                // Save in hex format for easier handling
                File.WriteAllText(keyOutputPath, BitConverter.ToString(key).Replace("-", ""));
            }

            return key;
        }

        /// <summary>
        /// Decrypt a file using the specified algorithm
        /// </summary>
        /// <param name="inputFilePath">Path to the encrypted file</param>
        /// <param name="outputFilePath">Path where the decrypted file should be saved</param>
        /// <param name="encryption">Encryption algorithm to use</param>
        /// <param name="key">Decryption key</param>
        /// <returns>True if decryption was successful</returns>
        public bool DecryptFile(string inputFilePath, string outputFilePath, IEncryption encryption, byte[] key)
        {
            if ( !File.Exists(inputFilePath) )
                throw new FileNotFoundException("Encrypted file not found", inputFilePath);

            try
            {
                // Read the encrypted file
                _logger.LogInformation("Reading encrypted file: {Path}", inputFilePath);
                byte[] encryptedData = File.ReadAllBytes(inputFilePath);

                // Decrypt the data
                _logger.LogInformation("Decrypting file data using {Algorithm}", encryption.GetType().Name);
                byte[] decryptedData = encryption.Decrypt(encryptedData, key);

                // Save the decrypted data
                _logger.LogInformation("Writing decrypted data to: {Path}", outputFilePath);
                File.WriteAllBytes(outputFilePath, decryptedData);

                return true;
            }
            catch ( CryptographicException ex )
            {
                _logger.LogError(ex, "Decryption failed. The key may be incorrect or the data may be corrupted.");
                return false;
            }
            catch ( Exception ex )
            {
                _logger.LogError(ex, "An error occurred during file decryption");
                return false;
            }
        }

        /// <summary>
        /// Load a key from a file
        /// </summary>
        /// <param name="keyFilePath">Path to the key file</param>
        /// <returns>The key as a byte array</returns>
        public byte[] LoadKeyFromFile(string keyFilePath)
        {
            if ( !File.Exists(keyFilePath) )
                throw new FileNotFoundException("Key file not found", keyFilePath);

            string keyHex = File.ReadAllText(keyFilePath).Trim();

            // Support both hex string and raw binary formats
            if ( IsHexString(keyHex) )
            {
                return ConvertHexStringToByteArray(keyHex);
            }
            else
            {
                return File.ReadAllBytes(keyFilePath);
            }
        }

        private bool IsHexString(string test)
        {
            // Check if string is a valid hex string
            return test.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
        }

        private byte[] ConvertHexStringToByteArray(string hex)
        {
            // Remove any non-hex characters (like spaces or dashes)
            hex = new string(hex.Where(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')).ToArray());

            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for ( int i = 0; i < NumberChars; i += 2 )
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }
    }
}
