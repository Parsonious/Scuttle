using System.Security.Cryptography;

namespace Scuttle.Encrypt.Strategies.RC2
{
    /// <summary>
    /// Standard implementation of RC2 encryption
    /// </summary>
    internal class RC2StandardStrategy : BaseRC2Strategy
    {
        public override int Priority => 100;
        public override string Description => "Standard RC2 Implementation";

        public override byte[] Encrypt(byte[] data, byte[] key)
        {
            ValidateInputs(data, key);

            byte[] iv = new byte[IVSize];
            RandomNumberGenerator.Fill(iv);

            using var rc2 = System.Security.Cryptography.RC2.Create();
            rc2.Key = key;
            rc2.IV = iv;

            using var msEncrypt = new MemoryStream();
            // Write IV to the beginning of the stream
            msEncrypt.Write(iv, 0, iv.Length);

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
            if ( encryptedData == null || encryptedData.Length < IVSize )
                throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));

            // Extract IV from the beginning of the encrypted data
            byte[] iv = new byte[IVSize];
            Buffer.BlockCopy(encryptedData, 0, iv, 0, IVSize);

            using var rc2 = System.Security.Cryptography.RC2.Create();
            rc2.Key = key;
            rc2.IV = iv;

            using var msDecrypt = new MemoryStream(encryptedData, IVSize, encryptedData.Length - IVSize);
            using var cryptoStream = new CryptoStream(msDecrypt, rc2.CreateDecryptor(), CryptoStreamMode.Read);
            using var reader = new BinaryReader(cryptoStream);

            int length = reader.ReadInt32(); // Read original length
            return reader.ReadBytes(length); // Read data
        }

        /// <summary>
        /// RC2 is supported on all platforms
        /// </summary>
        public static bool IsSupported => true;
    }
}
