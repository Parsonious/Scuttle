using System.Security.Cryptography;
using System.Buffers;

namespace Scuttle.Encrypt.Strategies.AesGcm
{
    /// <summary>
    /// Software fallback implementation of AES-GCM for platforms without hardware acceleration
    /// </summary>
    internal class AesGcmSoftwareStrategy : BaseAesGcmStrategy
    {
        public override int Priority => 100; // Lower priority than hardware implementation
        public override string Description => "Software AES-GCM Implementation";

        public override byte[] Encrypt(byte[] data, byte[] key)
        {
            ValidateInputs(data, key);

            // Calculate output size once
            int resultSize = NonceSize + data.Length + TagSize;
            byte[] result = new byte[resultSize];

            // Use temporary pooled buffers for processing
            byte[] nonce = ArrayPool<byte>.Shared.Rent(NonceSize);
            byte[] tag = ArrayPool<byte>.Shared.Rent(TagSize);

            try
            {
                // Generate cryptographically secure nonce
                RandomNumberGenerator.Fill(nonce.AsSpan(0, NonceSize));

                // Copy nonce to result
                Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);

                // Since we don't have hardware AES-GCM, we'll use AES-CBC + HMAC as a fallback
                using ( var aes = Aes.Create() )
                {
                    aes.Key = key;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    // Create a new IV (we'll still use the nonce but only first 16 bytes)
                    byte[] iv = new byte[16]; // AES block size
                    Buffer.BlockCopy(nonce, 0, iv, 0, Math.Min(NonceSize, 16));
                    aes.IV = iv;

                    // Encrypt the data
                    using ( var encryptor = aes.CreateEncryptor() )
                    using ( var ms = new MemoryStream() )
                    using ( var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write) )
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                        byte[] encryptedData = ms.ToArray();

                        // Since we're using CBC which has padding, our output size might be larger
                        // than expected. We'll adjust our result array if needed.
                        if ( encryptedData.Length != data.Length )
                        {
                            // Create a new result array with the correct size
                            byte[] newResult = new byte[NonceSize + encryptedData.Length + TagSize];
                            Buffer.BlockCopy(nonce, 0, newResult, 0, NonceSize);
                            Buffer.BlockCopy(encryptedData, 0, newResult, NonceSize, encryptedData.Length);

                            // Generate authentication tag (HMAC of nonce + ciphertext)
                            using ( var hmac = new HMACSHA256(key) )
                            {
                                hmac.TransformBlock(nonce, 0, NonceSize, null, 0);
                                hmac.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                                var fullTag = hmac.Hash!;

                                // Use just 16 bytes of the HMAC as our tag
                                Buffer.BlockCopy(fullTag, 0, newResult, NonceSize + encryptedData.Length, TagSize);
                            }

                            return newResult;
                        }
                        else
                        {
                            Buffer.BlockCopy(encryptedData, 0, result, NonceSize, data.Length);
                        }
                    }
                }

                // Generate authentication tag (HMAC of nonce + ciphertext)
                using ( var hmac = new HMACSHA256(key) )
                {
                    hmac.TransformBlock(nonce, 0, NonceSize, null, 0);
                    hmac.TransformFinalBlock(data, 0, data.Length);
                    var fullTag = hmac.Hash!;

                    // Use just 16 bytes of the HMAC as our tag
                    Buffer.BlockCopy(fullTag, 0, result, NonceSize + data.Length, TagSize);
                }

                return result;
            }
            finally
            {
                // Return rented arrays to pool
                ArrayPool<byte>.Shared.Return(nonce);
                ArrayPool<byte>.Shared.Return(tag);
            }
        }

        public override byte[] Decrypt(byte[] encryptedData, byte[] key)
        {
            if ( encryptedData == null || encryptedData.Length < NonceSize + TagSize )
                throw new ArgumentException($"Invalid encrypted data. Minimum length is {NonceSize + TagSize} bytes.", nameof(encryptedData));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));

            // Extract nonce and ciphertext
            byte[] nonce = new byte[NonceSize];
            Buffer.BlockCopy(encryptedData, 0, nonce, 0, NonceSize);

            int ciphertextLength = encryptedData.Length - NonceSize - TagSize;
            byte[] ciphertext = new byte[ciphertextLength];
            Buffer.BlockCopy(encryptedData, NonceSize, ciphertext, 0, ciphertextLength);

            byte[] tag = new byte[TagSize];
            Buffer.BlockCopy(encryptedData, NonceSize + ciphertextLength, tag, 0, TagSize);

            // Verify the tag
            using ( var hmac = new HMACSHA256(key) )
            {
                hmac.TransformBlock(nonce, 0, NonceSize, null, 0);
                hmac.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                var computedTag = hmac.Hash!;

                // Use constant-time comparison to prevent timing attacks
                if ( !ConstantTimeEquals(computedTag.AsSpan(0, TagSize), tag) )
                {
                    throw new CryptographicException("Authentication failed.");
                }
            }

            // Decrypt using AES-CBC
            using ( var aes = Aes.Create() )
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                // Create IV from nonce
                byte[] iv = new byte[16];
                Buffer.BlockCopy(nonce, 0, iv, 0, Math.Min(NonceSize, 16));
                aes.IV = iv;

                // Decrypt the data
                using ( var decryptor = aes.CreateDecryptor() )
                using ( var ms = new MemoryStream(ciphertext) )
                using ( var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read) )
                using ( var resultStream = new MemoryStream() )
                {
                    cs.CopyTo(resultStream);
                    return resultStream.ToArray();
                }
            }
        }

        // The software implementation doesn't support parallel processing efficiently
        public override byte[] EncryptParallel(byte[] data, byte[] key) => Encrypt(data, key);
        public override byte[] DecryptParallel(byte[] encryptedData, byte[] key) => Decrypt(encryptedData, key);

        // The software implementation is always supported as a fallback
        public static bool IsSupported => true;
    }
}
