using System.Buffers;
using System.Security.Cryptography;
using Scuttle.Base;
using Scuttle.Encrypt.BernSteinCore;
using Scuttle.Encrypt.Strategies.Salsa20;
using Scuttle.Interfaces;

namespace Scuttle.Encrypt
{
    /// <summary>
    /// Implementation of the Salsa20 stream cipher by Daniel J. Bernstein using the strategy pattern
    /// for optimal hardware-specific implementations.
    /// </summary>
    internal class Salsa20Encrypt : BaseEncryption
    {
        private const int KeySize = ChaChaConstants.KeySize;    // 256 bits
        private const int NonceSize = ChaChaConstants.Salsa20NonceSize;                        // 64 bits for Salsa20

        private readonly ISalsa20Strategy _strategy;

        /// <summary>
        /// Creates a new Salsa20 encryptor that automatically selects the optimal
        /// implementation for the current hardware
        /// </summary>
        public Salsa20Encrypt(IEncoder encoder) : base(encoder)
        {
            _strategy = Salsa20StrategyFactory.GetBestStrategy();
        }

        /// <summary>
        /// For testing - allows injection of a specific strategy
        /// </summary>
        internal Salsa20Encrypt(IEncoder encoder, ISalsa20Strategy strategy) : base(encoder)
        {
            _strategy = strategy;
        }

        public override byte[] Encrypt(byte[] data, byte[] key)
        {
            if ( data == null || data.Length == 0 )
                throw new ArgumentException("Data cannot be null or empty.", nameof(data));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes (found {key?.Length ?? 0} bytes).", nameof(key));

            // Use ArrayPool for better memory management
            byte[] nonce = ArrayPool<byte>.Shared.Rent(NonceSize);
            byte[] ciphertext = ArrayPool<byte>.Shared.Rent(data.Length);

            try
            {
                // Generate secure random nonce
                RandomNumberGenerator.Fill(nonce.AsSpan(0, NonceSize));

                // Let the strategy handle the encryption
                _strategy.ProcessBlock(key, nonce.AsSpan(0, NonceSize), data, ciphertext);

                // Combine nonce and ciphertext
                byte[] result = new byte[NonceSize + data.Length];
                Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
                Buffer.BlockCopy(ciphertext, 0, result, NonceSize, data.Length);

                return result;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(nonce);
                ArrayPool<byte>.Shared.Return(ciphertext);
            }
        }

        public override byte[] Decrypt(byte[] encryptedData, byte[] key)
        {
            if ( encryptedData == null || encryptedData.Length < NonceSize )
                throw new ArgumentException($"Invalid encrypted data. Minimum length is {NonceSize} bytes.", nameof(encryptedData));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes (found {key?.Length ?? 0} bytes).", nameof(key));

            // Extract nonce using spans to avoid copying
            ReadOnlySpan<byte> nonceSpan = encryptedData.AsSpan(0, NonceSize);

            // Calculate actual ciphertext size
            int ciphertextLength = encryptedData.Length - NonceSize;
            ReadOnlySpan<byte> ciphertextSpan = encryptedData.AsSpan(NonceSize, ciphertextLength);

            // Create output array and decrypt directly using the strategy
            byte[] plaintext = new byte[ciphertextLength];
            _strategy.ProcessBlock(key, nonceSpan, ciphertextSpan, plaintext);

            return plaintext;
        }

        public override byte[] GenerateKey()
        {
            byte[] key = new byte[KeySize];
            RandomNumberGenerator.Fill(key);
            return key;
        }
    }
}
