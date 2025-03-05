using System.Security.Cryptography;
using Scuttle.Base;
using Scuttle.Encrypt.Strategies.AES;
using Scuttle.Encrypt.Strategies.AesGcm;
using Scuttle.Interfaces;

namespace Scuttle.Encrypt
{
    /// <summary>
    /// AES-GCM authenticated encryption implementation using the strategy pattern
    /// to select the optimal implementation for the current hardware.
    /// </summary>
    internal class AesGcmEncrypt : BaseEncryption
    {
        private readonly IAesGcmStrategy _strategy;

        /// <summary>
        /// Creates a new AES-GCM encryptor that automatically selects the optimal
        /// implementation for the current hardware
        /// </summary>
        public AesGcmEncrypt(IEncoder encoder) : base(encoder)
        {
            _strategy = AesGcmStrategyFactory.GetBestStrategy();
        }

        /// <summary>
        /// For testing - allows injection of a specific strategy
        /// </summary>
        internal AesGcmEncrypt(IEncoder encoder, IAesGcmStrategy strategy) : base(encoder)
        {
            _strategy = strategy;
        }

        public override byte[] Encrypt(byte[] data, byte[] key)
        {
            return _strategy.Encrypt(data, key);
        }

        public override byte[] Decrypt(byte[] encryptedData, byte[] key)
        {
            return _strategy.Decrypt(encryptedData, key);
        }

        /// <summary>
        /// Encrypts large data using parallel processing for better performance
        /// </summary>
        public byte[] EncryptParallel(byte[] data, byte[] key)
        {
            return _strategy.EncryptParallel(data, key);
        }

        /// <summary>
        /// Decrypts data that was encrypted with EncryptParallel
        /// </summary>
        public byte[] DecryptParallel(byte[] encryptedData, byte[] key)
        {
            return _strategy.DecryptParallel(encryptedData, key);
        }

        public override byte[] GenerateKey()
        {
            byte[] key = new byte[32]; // 256 bits
            RandomNumberGenerator.Fill(key);
            return key;
        }
    }
}
