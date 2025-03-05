using System;
using System.Security.Cryptography;
using Scuttle.Base;
using Scuttle.Interfaces;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace Scuttle.Encrypt
{
    /// <summary>
    /// AES-GCM authenticated encryption implementation using .NET's built-in AesGcm class.
    /// This provides confidentiality, integrity, and authenticity of data with high performance.
    /// </summary>
    /// <remarks>
    /// AES-GCM operates in one pass and offers better performance than separate
    /// encryption and authentication schemes. It requires hardware support for
    /// optimal performance, which is available on most modern processors.
    /// </remarks>
    internal class AesGcmEncrypt : BaseEncryption
    {
        private const int KeySize = 32;    // 256 bits
        private const int NonceSize = 12;  // 96 bits for GCM
        private const int TagSize = 16;    // 128 bits for Authentication Tag

        // Cache for AesGcm instances to avoid recreating them for repeated operations
        private static readonly ConditionalWeakTable<byte[], AesGcmWrapper> KeyCache =
            new ConditionalWeakTable<byte[], AesGcmWrapper>();

        // Check if hardware acceleration is available
        private static readonly bool IsAesHardwareAccelerated = AesGcm.IsSupported;

        public AesGcmEncrypt(IEncoder encoder) : base(encoder)
        {
            if ( !IsAesHardwareAccelerated )
            {
                // Log a warning that hardware acceleration isn't available
                Console.WriteLine("Warning: AES hardware acceleration is not available. Performance may be reduced.");
            }
        }

        /// <summary>
        /// Wrapper class for AesGcm to handle proper lifecycle and provide expiration
        /// </summary>
        private class AesGcmWrapper : IDisposable
        {
            public AesGcm AesGcm { get; }
            private readonly DateTime _created;
            private readonly TimeSpan _maxAge = TimeSpan.FromMinutes(10); // Configurable expiration

            public AesGcmWrapper(byte[] key, int tagSize)
            {
                AesGcm = new AesGcm(key, tagSize);
                _created = DateTime.UtcNow;
            }

            public bool IsExpired => DateTime.UtcNow - _created > _maxAge;

            public void Dispose()
            {
                AesGcm.Dispose();
            }
        }

        /// <summary>
        /// Gets or creates an AesGcm instance from the cache for the specified key
        /// </summary>
        private AesGcm GetAesGcm(byte[] key)
        {
            // Clean expired entries when getting a new instance
            if ( !KeyCache.TryGetValue(key, out var wrapper) || wrapper.IsExpired )
            {
                // Remove old instance if exists
                if ( wrapper != null )
                {
                    wrapper.Dispose();
                    KeyCache.Remove(key);
                }

                // Create new instance
                wrapper = new AesGcmWrapper(key, TagSize);
                KeyCache.Add(key, wrapper);
            }

            return wrapper.AesGcm;
        }

        /// <summary>
        /// Encrypts data using AES-GCM authenticated encryption
        /// </summary>
        /// <param name="data">The data to encrypt</param>
        /// <param name="key">The encryption key (32 bytes for AES-256)</param>
        /// <returns>Encrypted data with nonce and authentication tag</returns>
        public override byte[] Encrypt(byte[] data, byte[] key)
        {
            ValidateInputs(data, key);

            // Calculate output size once
            int resultSize = NonceSize + data.Length + TagSize;
            byte[] result = new byte[resultSize];

            // Use temporary pooled buffers for processing
            byte[] nonce = ArrayPool<byte>.Shared.Rent(NonceSize);

            try
            {
                // Generate cryptographically secure nonce
                RandomNumberGenerator.Fill(nonce.AsSpan(0, NonceSize));

                // Use Span<T> for zero-copy operations where possible
                Span<byte> resultSpan = result.AsSpan();
                nonce.AsSpan(0, NonceSize).CopyTo(resultSpan.Slice(0, NonceSize));

                // Get AesGcm instance from cache
                AesGcm aesGcm = GetAesGcm(key);

                // Encrypt directly into the result array to avoid extra copying
                aesGcm.Encrypt(
                    nonce.AsSpan(0, NonceSize),
                    data,
                    resultSpan.Slice(NonceSize, data.Length),
                    resultSpan.Slice(NonceSize + data.Length, TagSize));

                return result;
            }
            finally
            {
                // Return rented arrays to pool
                ArrayPool<byte>.Shared.Return(nonce);
            }
        }

        /// <summary>
        /// Decrypts data that was encrypted with AES-GCM
        /// </summary>
        /// <param name="encryptedData">The encrypted data including nonce and authentication tag</param>
        /// <param name="key">The encryption key (32 bytes for AES-256)</param>
        /// <returns>The decrypted data</returns>
        /// <exception cref="CryptographicException">Thrown when authentication fails</exception>
        public override byte[] Decrypt(byte[] encryptedData, byte[] key)
        {
            if ( encryptedData == null || encryptedData.Length < NonceSize + TagSize )
                throw new ArgumentException($"Invalid encrypted data. Minimum length is {NonceSize + TagSize} bytes.", nameof(encryptedData));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes (found {key?.Length ?? 0} bytes).", nameof(key));

            // Extract components using spans to avoid unnecessary copying
            ReadOnlySpan<byte> encryptedSpan = encryptedData;
            ReadOnlySpan<byte> nonce = encryptedSpan.Slice(0, NonceSize);

            int ciphertextLength = encryptedData.Length - NonceSize - TagSize;
            ReadOnlySpan<byte> ciphertext = encryptedSpan.Slice(NonceSize, ciphertextLength);
            ReadOnlySpan<byte> tag = encryptedSpan.Slice(NonceSize + ciphertextLength, TagSize);

            // Create result array
            byte[] plaintext = new byte[ciphertextLength];

            try
            {
                // Get AesGcm instance from cache
                AesGcm aesGcm = GetAesGcm(key);

                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
                return plaintext;
            }
            catch ( CryptographicException )
            {
                throw new CryptographicException("Decryption failed. The data may have been tampered with or the wrong key was provided.");
            }
        }

        /// <summary>
        /// Generates a cryptographically secure random key for AES-GCM
        /// </summary>
        /// <returns>A 32-byte key suitable for AES-256-GCM</returns>
        public override byte[] GenerateKey()
        {
            byte[] key = new byte[KeySize];
            RandomNumberGenerator.Fill(key);
            return key;
        }

        /// <summary>
        /// Encrypts large data using parallel processing for better performance
        /// </summary>
        /// <param name="data">The data to encrypt</param>
        /// <param name="key">The encryption key</param>
        /// <returns>The encrypted data</returns>
        /// <remarks>
        /// This method is recommended for large data sets (>1MB).
        /// It divides the data into chunks and processes them in parallel.
        /// </remarks>
        public byte[] EncryptParallel(byte[] data, byte[] key)
        {
            ValidateInputs(data, key);

            // Only use parallel processing for large data
            if ( data.Length < 1024 * 1024 ) // 1MB threshold
                return Encrypt(data, key);

            // Calculate chunk size
            int processorCount = Environment.ProcessorCount;
            int chunkSize = Math.Max(1024 * 64, data.Length / processorCount); // At least 64KB chunks
            int chunkCount = (data.Length + chunkSize - 1) / chunkSize;

            // Generate master nonce
            byte[] masterNonce = new byte[NonceSize];
            RandomNumberGenerator.Fill(masterNonce);

            // Create result array
            byte[] result = new byte[NonceSize + data.Length + TagSize];
            Buffer.BlockCopy(masterNonce, 0, result, 0, NonceSize);

            // Create an array to store chunk tags
            byte[][] chunkTags = new byte[chunkCount][];
            for ( int i = 0; i < chunkCount; i++ )
            {
                chunkTags[i] = new byte[TagSize];
            }

            // Process chunks in parallel
            Parallel.For(0, chunkCount, i =>
            {
                int offset = i * chunkSize;
                int length = Math.Min(chunkSize, data.Length - offset);

                // Create unique nonce for each chunk by XORing counter with base nonce
                byte[] chunkNonce = (byte[]) masterNonce.Clone();
                BitConverter.GetBytes(i).AsSpan().CopyTo(chunkNonce.AsSpan(NonceSize - 4, 4));

                using var aesGcm = new AesGcm(key, TagSize);

                aesGcm.Encrypt(
                    chunkNonce,
                    data.AsSpan(offset, length),
                    result.AsSpan(NonceSize + offset, length),
                    chunkTags[i]);
            });

            // For the final tag, compute a tag over all chunk tags
            using ( var hmac = new HMACSHA256(key) )
            {
                byte[] combinedTag = hmac.ComputeHash(CombineChunkTags(chunkTags));
                Buffer.BlockCopy(combinedTag, 0, result, NonceSize + data.Length, TagSize);
            }

            return result;
        }

        /// <summary>
        /// Decrypts data that was encrypted with EncryptParallel
        /// </summary>
        /// <param name="encryptedData">The encrypted data</param>
        /// <param name="key">The encryption key</param>
        /// <returns>The decrypted data</returns>
        public byte[] DecryptParallel(byte[] encryptedData, byte[] key)
        {
            if ( encryptedData == null || encryptedData.Length < NonceSize + TagSize )
                throw new ArgumentException($"Invalid encrypted data. Minimum length is {NonceSize + TagSize} bytes.", nameof(encryptedData));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes (found {key?.Length ?? 0} bytes).", nameof(key));

            // For small data, use the regular decrypt method
            if ( encryptedData.Length < 1024 * 1024 + NonceSize + TagSize )
                return Decrypt(encryptedData, key);

            // Extract the master nonce
            byte[] masterNonce = new byte[NonceSize];
            Buffer.BlockCopy(encryptedData, 0, masterNonce, 0, NonceSize);

            // Verify the combined tag
            int dataLength = encryptedData.Length - NonceSize - TagSize;
            byte[] tag = new byte[TagSize];
            Buffer.BlockCopy(encryptedData, NonceSize + dataLength, tag, 0, TagSize);

            // Create result array
            byte[] plaintext = new byte[dataLength];

            // Calculate chunk size
            int processorCount = Environment.ProcessorCount;
            int chunkSize = Math.Max(1024 * 64, dataLength / processorCount); // At least 64KB chunks
            int chunkCount = (dataLength + chunkSize - 1) / chunkSize;

            // Create an array to store chunk tags
            byte[][] chunkTags = new byte[chunkCount][];
            for ( int i = 0; i < chunkCount; i++ )
            {
                chunkTags[i] = new byte[TagSize];
            }

            // Process chunks in parallel
            Parallel.For(0, chunkCount, i =>
            {
                int offset = i * chunkSize;
                int length = Math.Min(chunkSize, dataLength - offset);

                // Create unique nonce for this chunk
                byte[] chunkNonce = (byte[]) masterNonce.Clone();
                BitConverter.GetBytes(i).AsSpan().CopyTo(chunkNonce.AsSpan(NonceSize - 4, 4));

                using var aesGcm = new AesGcm(key, TagSize);

                try
                {
                    aesGcm.Decrypt(
                        chunkNonce,
                        encryptedData.AsSpan(NonceSize + offset, length),
                        encryptedData.AsSpan(NonceSize + dataLength, TagSize),
                        plaintext.AsSpan(offset, length));

                    // Store the tag for this chunk
                    Buffer.BlockCopy(encryptedData, NonceSize + dataLength, chunkTags[i], 0, TagSize);
                }
                catch ( CryptographicException )
                {
                    throw new CryptographicException($"Decryption failed for chunk {i}");
                }
            });

            // Verify overall tag
            using ( var hmac = new HMACSHA256(key) )
            {
                byte[] expectedTag = hmac.ComputeHash(CombineChunkTags(chunkTags));
                if ( !ConstantTimeEquals(expectedTag.AsSpan(0, TagSize), tag) )
                {
                    throw new CryptographicException("Authentication failed for the combined data");
                }
            }

            return plaintext;
        }

        /// <summary>
        /// Helper method to combine chunk tags for verification
        /// </summary>
        private byte[] CombineChunkTags(byte[][] chunkTags)
        {
            byte[] combined = new byte[chunkTags.Length * TagSize];
            for ( int i = 0; i < chunkTags.Length; i++ )
            {
                Buffer.BlockCopy(chunkTags[i], 0, combined, i * TagSize, TagSize);
            }
            return combined;
        }

        /// <summary>
        /// Constant-time comparison of two byte spans to prevent timing attacks
        /// </summary>
        private bool ConstantTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
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
        /// Validates input parameters for encryption methods
        /// </summary>
        private void ValidateInputs(byte[] data, byte[] key)
        {
            if ( data == null || data.Length == 0 )
                throw new ArgumentException("Data cannot be null or empty.", nameof(data));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes (found {key?.Length ?? 0} bytes).", nameof(key));
        }
    }
}
