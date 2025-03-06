using System.Security.Cryptography;

namespace Scuttle.Encrypt.Strategies.RC2
{
    /// <summary>
    /// Enhanced implementation of RC2 with additional security features
    /// </summary>
    internal class RC2EnhancedStrategy : BaseRC2Strategy
    {
        public override int Priority => 200;
        public override string Description => "Enhanced RC2 Implementation";

        // Effective key bits - the higher the better, but RC2 supports up to 128 bits (1 to 1024 bits)
        private const int _effectiveKeySizeBits = 128;

        public override byte[] Encrypt(byte[] data, byte[] key)
        {
            ValidateInputs(data, key);

            byte[] iv = new byte[IVSize];
            RandomNumberGenerator.Fill(iv);

            // Use derived key with PBKDF2 for better security
            using var pbkdf2 = new Rfc2898DeriveBytes(key, iv, 10000, HashAlgorithmName.SHA256);
            byte[] derivedKey = pbkdf2.GetBytes(KeySize);

            using var rc2 = System.Security.Cryptography.RC2.Create();
            rc2.Key = derivedKey;
            rc2.IV = iv;
            rc2.EffectiveKeySize = _effectiveKeySizeBits;

            using var msEncrypt = new MemoryStream();
            // Write IV to the beginning of the stream
            msEncrypt.Write(iv, 0, iv.Length);

            // Also include a SHA256 hash of the original data for integrity checking
            byte[] hash = SHA256.HashData(data);
            msEncrypt.Write(hash, 0, hash.Length);

            using ( var cryptoStream = new CryptoStream(msEncrypt, rc2.CreateEncryptor(), CryptoStreamMode.Write) )
            using ( var writer = new BinaryWriter(cryptoStream) )
            {
                writer.Write(data.Length); // Write original length
                writer.Write(data);        // Write data
            }

            return msEncrypt.ToArray();
        }

        public override byte[] Decrypt(byte[] encryptedData, byte[] key)
        {
            if ( encryptedData == null || encryptedData.Length < IVSize + 32 ) // IV + SHA256 hash
                throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));

            // Extract IV from the beginning of the encrypted data
            byte[] iv = new byte[IVSize];
            Buffer.BlockCopy(encryptedData, 0, iv, 0, IVSize);

            // Extract the hash
            byte[] storedHash = new byte[32]; // SHA256 hash is 32 bytes
            Buffer.BlockCopy(encryptedData, IVSize, storedHash, 0, 32);

            // Use derived key with PBKDF2 for better security
            using var pbkdf2 = new Rfc2898DeriveBytes(key, iv, 10000, HashAlgorithmName.SHA256);
            byte[] derivedKey = pbkdf2.GetBytes(KeySize);

            using var rc2 = System.Security.Cryptography.RC2.Create();
            rc2.Key = derivedKey;
            rc2.IV = iv;
            rc2.EffectiveKeySize = _effectiveKeySizeBits;

            using var msDecrypt = new MemoryStream(encryptedData, IVSize + 32, encryptedData.Length - IVSize - 32);
            using var cryptoStream = new CryptoStream(msDecrypt, rc2.CreateDecryptor(), CryptoStreamMode.Read);
            using var reader = new BinaryReader(cryptoStream);

            int length = reader.ReadInt32(); // Read original length
            byte[] decryptedData = reader.ReadBytes(length); // Read data

            // Verify integrity using the stored hash
            byte[] computedHash = SHA256.HashData(decryptedData);

            // Compare hashes in constant time to prevent timing attacks
            if ( !ConstantTimeEquals(storedHash, computedHash) )
            {
                throw new CryptographicException("Data integrity check failed. The data may have been tampered with.");
            }

            return decryptedData;
        }

        /// <summary>
        /// Constant-time comparison of two byte arrays to prevent timing attacks
        /// </summary>
        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if ( a.Length != b.Length )
                return false;

            int result = 0;
            for ( int i = 0; i < a.Length; i++ )
            {
                result |= a[i] ^ b[i];
            }

            return result == 0;
        }

        /// <summary>
        /// Enhanced RC2 is supported on all platforms
        /// </summary>
        public static bool IsSupported => true;
    }
}
