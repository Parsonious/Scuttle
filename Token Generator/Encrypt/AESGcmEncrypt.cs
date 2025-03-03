using System;
using System.Security.Cryptography;
using System.Text;
using Token_Generator.AES;
using Token_Generator.Encoders;
using Token_Generator.Interfaces;

namespace Token_Generator.Encrypt
{
    internal class AesGcmEncrypt : IEncryption
    {
        private const int KeySize = 32;    // 256 bits
        private const int NonceSize = 12;  // 96 bits for GCM
        private const int TagSize = 16;    // 128 bits for Authentication Tag

        public enum EncodingType
        {
            Base64,
            Base65536
        }

        private readonly EncodingType _encodingType;

        public AesGcmEncrypt(EncodingType encodingType = EncodingType.Base64)
        {
            _encodingType = encodingType;
        }

        public byte[] Encrypt(byte[] data, byte[] key)
        {
            if ( data == null || data.Length == 0 )
                throw new ArgumentException("Data cannot be null or empty.", nameof(data));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));

            using var aesGcm = new AesGcm(key, TagSize);

            // Generate a new nonce for each encryption
            byte[] nonce = new byte[NonceSize];
            RandomNumberGenerator.Fill(nonce);

            // Allocate space for the ciphertext and tag
            byte[] ciphertext = new byte[data.Length];
            byte[] tag = new byte[TagSize];

            // Encrypt the data
            aesGcm.Encrypt(nonce, data, ciphertext, tag);

            // Combine nonce + ciphertext + tag into a single array
            byte[] result = new byte[NonceSize + data.Length + TagSize];
            Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
            Buffer.BlockCopy(ciphertext, 0, result, NonceSize, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, NonceSize + ciphertext.Length, TagSize);

            return result;
        }

        public byte[] Decrypt(byte[] encryptedData, byte[] key)
        {
            if ( encryptedData == null || encryptedData.Length < NonceSize + TagSize )
                throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));

            using var aesGcm = new AesGcm(key, TagSize);

            // Extract nonce, ciphertext, and tag
            byte[] nonce = new byte[NonceSize];
            Buffer.BlockCopy(encryptedData, 0, nonce, 0, NonceSize);

            int ciphertextLength = encryptedData.Length - NonceSize - TagSize;
            byte[] ciphertext = new byte[ciphertextLength];
            Buffer.BlockCopy(encryptedData, NonceSize, ciphertext, 0, ciphertextLength);

            byte[] tag = new byte[TagSize];
            Buffer.BlockCopy(encryptedData, NonceSize + ciphertextLength, tag, 0, TagSize);

            // Decrypt the data
            byte[] plaintext = new byte[ciphertextLength];
            try
            {
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
                return plaintext;
            }
            catch ( CryptographicException )
            {
                throw new CryptographicException("Decryption failed. The data may have been tampered with or the wrong key was used.");
            }
        }

        public string EncryptAndEncode(string data, byte[] key)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(data);
            byte[] encryptedBytes = Encrypt(plainBytes, key);

            return _encodingType switch
            {
                EncodingType.Base65536 => Base65536.Encode(encryptedBytes),
                _ => Convert.ToBase64String(encryptedBytes)
            };
        }

        public string DecodeAndDecrypt(string encodedData, byte[] key)
        {
            byte[] encryptedBytes = _encodingType switch
            {
                EncodingType.Base65536 => Base65536.Decode(encodedData),
                _ => Convert.FromBase64String(encodedData)
            };

            byte[] decryptedBytes = Decrypt(encryptedBytes, key);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        public byte[] GenerateKey()
        {
            byte[] key = new byte[KeySize];
            RandomNumberGenerator.Fill(key);
            return key;
        }
    }
}