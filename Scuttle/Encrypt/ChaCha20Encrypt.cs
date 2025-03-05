using System.Buffers;
using System.Security.Cryptography;
using Scuttle.Base;
using Scuttle.Encrypt.BernSteinCore;
using Scuttle.Encrypt.Strategies.ChaCha20;
using Scuttle.Factories;
using Scuttle.Interfaces;

namespace Scuttle.Encrypt
{
    /// <summary>
    /// Implementation of the ChaCha20 stream cipher with Poly1305 authentication using the strategy pattern
    /// for optimal hardware-specific implementations.
    /// </summary>
    internal class ChaCha20Encrypt : BaseEncryption
    {
        private const int KeySize = ChaChaConstants.KeySize;    // 256 bits
        private const int NonceSize = ChaChaConstants.ChaCha20NonceSize;  // 96 bits
        private const int TagSize = ChaChaConstants.TagSize;    // 128 bits for Poly1305

        private readonly IChaCha20Strategy _strategy;

        /// <summary>
        /// Creates a new ChaCha20 encryptor that automatically selects the optimal
        /// implementation for the current hardware
        /// </summary>
        public ChaCha20Encrypt(IEncoder encoder) : base(encoder)
        {
            _strategy = ChaCha20StrategyFactory.GetBestStrategy();
        }

        /// <summary>
        /// For testing - allows injection of a specific strategy
        /// </summary>
        internal ChaCha20Encrypt(IEncoder encoder, IChaCha20Strategy strategy) : base(encoder)
        {
            _strategy = strategy;
        }

        public override byte[] Encrypt(byte[] data, byte[] key)
        {
            if ( data == null || data.Length == 0 )
                throw new ArgumentException("Data cannot be null or empty.", nameof(data));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));

            // Use ArrayPool for better memory management
            byte[] nonce = ArrayPool<byte>.Shared.Rent(NonceSize);
            byte[] ciphertext = ArrayPool<byte>.Shared.Rent(data.Length);

            try
            {
                RandomNumberGenerator.Fill(nonce.AsSpan(0, NonceSize));

                // Encrypt the data using the strategy
                _strategy.ProcessBlock(key, nonce.AsSpan(0, NonceSize), data, ciphertext);

                // Calculate Poly1305 auth tag using keystream from the strategy
                byte[] poly1305Key = _strategy.GenerateKeyStream(key, nonce.AsSpan(0, NonceSize), KeySize);
                byte[] tag = Poly1305.ComputeTag(poly1305Key, ciphertext.AsSpan(0, data.Length));

                // Combine nonce, ciphertext, and tag
                byte[] result = new byte[NonceSize + data.Length + TagSize];
                Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
                Buffer.BlockCopy(ciphertext, 0, result, NonceSize, data.Length);
                Buffer.BlockCopy(tag, 0, result, NonceSize + data.Length, TagSize);

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
            if ( encryptedData == null || encryptedData.Length < NonceSize + TagSize )
                throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));

            // Extract components using spans to avoid unnecessary allocations
            ReadOnlySpan<byte> nonceSpan = encryptedData.AsSpan(0, NonceSize);
            int ciphertextLength = encryptedData.Length - NonceSize - TagSize;
            ReadOnlySpan<byte> ciphertextSpan = encryptedData.AsSpan(NonceSize, ciphertextLength);
            ReadOnlySpan<byte> tagSpan = encryptedData.AsSpan(NonceSize + ciphertextLength, TagSize);

            // Verify MAC
            byte[] poly1305Key = _strategy.GenerateKeyStream(key, nonceSpan, KeySize);
            byte[] computedTag = Poly1305.ComputeTag(poly1305Key, ciphertextSpan);

            if ( !ChaChaUtils.ConstantTimeEquals(tagSpan, computedTag.AsSpan()) )
                throw new CryptographicException("Authentication failed.");

            // Decrypt data using the strategy
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
