using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Scuttle.Encrypt.Strategies.AesGcm
{
    /// <summary>
    /// Hardware-accelerated implementation of AES-GCM
    /// </summary>
    internal class AesGcmHardwareStrategy : BaseAesGcmStrategy
    {
        public override int Priority => 200;
        public override string Description => "Hardware-Accelerated AES-GCM";

        // Cache for AesGcm instances to avoid recreating them for repeated operations
        private static readonly ConditionalWeakTable<byte[], AesGcmWrapper> KeyCache =
            new ConditionalWeakTable<byte[], AesGcmWrapper>();

        /// <summary>
        /// Wrapper class for AesGcm to handle proper lifecycle and provide expiration
        /// </summary>
        private class AesGcmWrapper : IDisposable
        {
            public System.Security.Cryptography.AesGcm AesGcm { get; }
            private readonly DateTime _created;
            private readonly TimeSpan _maxAge = TimeSpan.FromMinutes(10); // Configurable expiration

            public AesGcmWrapper(byte[] key, int tagSize)
            {
                AesGcm = new System.Security.Cryptography.AesGcm(key, tagSize);
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
        private static System.Security.Cryptography.AesGcm GetAesGcm(byte[] key)
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
                System.Security.Cryptography.AesGcm aesGcm = GetAesGcm(key);

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
                System.Security.Cryptography.AesGcm aesGcm = GetAesGcm(key);

                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
                return plaintext;
            }
            catch ( CryptographicException )
            {
                throw new CryptographicException("Decryption failed. The data may have been tampered with or the wrong key was provided.");
            }
        }

        public override byte[] EncryptParallel(byte[] data, byte[] key)
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

                using var aesGcm = new System.Security.Cryptography.AesGcm(key, TagSize);

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

        public override byte[] DecryptParallel(byte[] encryptedData, byte[] key)
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

                using var aesGcm = new System.Security.Cryptography.AesGcm(key, TagSize);

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
        private static byte[] CombineChunkTags(byte[][] chunkTags)
        {
            byte[] combined = new byte[chunkTags.Length * TagSize];
            for ( int i = 0; i < chunkTags.Length; i++ )
            {
                Buffer.BlockCopy(chunkTags[i], 0, combined, i * TagSize, TagSize);
            }
            return combined;
        }

        /// <summary>
        /// Check if hardware acceleration is available for AES-GCM
        /// </summary>
        public static bool IsSupported => System.Security.Cryptography.AesGcm.IsSupported;
    }
}

