using System;
using System.Security.Cryptography;
using Scuttle.Enums;
using Scuttle.Base;
using Scuttle.Interfaces;

namespace Scuttle.Encrypt
{
    internal class AesGcmEncrypt : BaseEncryption
    {
        private const int KeySize = 32;    // 256 bits
        private const int NonceSize = 12;  // 96 bits for GCM
        private const int TagSize = 16;    // 128 bits for Authentication Tag
        private readonly EncodingType _encodingType;

        public AesGcmEncrypt(IEncoder encoder) : base(encoder)
        {
        }



        public override byte[] Encrypt(byte[] data, byte[] key)
        {
            if ( data == null || data.Length == 0 )
                throw new ArgumentException("Data cannot be null or empty.", nameof(data));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));

            using var aesGcm = new AesGcm(key, TagSize);
            byte[] nonce = new byte[NonceSize];
            RandomNumberGenerator.Fill(nonce);

            byte[] ciphertext = new byte[data.Length];
            byte[] tag = new byte[TagSize];
            aesGcm.Encrypt(nonce, data, ciphertext, tag);

            byte[] result = new byte[NonceSize + data.Length + TagSize];
            Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
            Buffer.BlockCopy(ciphertext, 0, result, NonceSize, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, NonceSize + ciphertext.Length, TagSize);

            return result;
        }

        public override byte[] Decrypt(byte[] encryptedData, byte[] key)
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

        public override byte[] GenerateKey()
        {
            byte[] key = new byte[KeySize];
            RandomNumberGenerator.Fill(key);
            return key;
        }
    }
}