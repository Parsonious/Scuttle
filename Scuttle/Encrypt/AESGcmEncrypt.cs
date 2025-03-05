using System;
using System.Security.Cryptography;
using Scuttle.Enums;
using Scuttle.Base;
using Scuttle.Interfaces;
using System.Buffers;

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

            // Use ArrayPool instead of new allocations for large buffers
            byte[] result = ArrayPool<byte>.Shared.Rent(NonceSize + data.Length + TagSize);
            byte[] tag = ArrayPool<byte>.Shared.Rent(TagSize);
            byte[] nonce = ArrayPool<byte>.Shared.Rent(NonceSize);
            byte[] ciphertext = ArrayPool<byte>.Shared.Rent(data.Length);
            try
    {
                RandomNumberGenerator.Fill(nonce.AsSpan(0, NonceSize));

                using var aesGcm = new AesGcm(key, TagSize);
                aesGcm.Encrypt(
                    nonce.AsSpan(0, NonceSize),
                    data.AsSpan(),
                    ciphertext.AsSpan(0, data.Length),
                    tag.AsSpan(0, TagSize));

                // Combine results into a single buffer
                Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
                Buffer.BlockCopy(ciphertext, 0, result, NonceSize, data.Length);
                Buffer.BlockCopy(tag, 0, result, NonceSize + data.Length, TagSize);

                // Create a properly sized output array
                byte[] output = new byte[NonceSize + data.Length + TagSize];
                Buffer.BlockCopy(result, 0, output, 0, output.Length);
                return output;
            }
            finally
            {
                // Return rented arrays
                ArrayPool<byte>.Shared.Return(result);
                ArrayPool<byte>.Shared.Return(tag);
                ArrayPool<byte>.Shared.Return(nonce);
                ArrayPool<byte>.Shared.Return(ciphertext);
            }
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