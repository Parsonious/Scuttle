using System.Security.Cryptography;
using Scuttle.Base;
using Scuttle.Encrypt.Strategies.RC2;
using Scuttle.Interfaces;

namespace Scuttle.Encrypt
{
    /// <summary>
    /// RC2 encryption implementation using the strategy pattern
    /// to select the optimal implementation.
    /// </summary>
    internal class RC2Encrypt : BaseEncryption
    {
        private readonly IRC2Strategy _strategy;

        /// <summary>
        /// Creates a new RC2 encryptor that automatically selects the optimal
        /// implementation
        /// </summary>
        public RC2Encrypt(IEncoder encoder) : base(encoder)
        {
            _strategy = RC2StrategyFactory.GetBestStrategy();
        }

        /// <summary>
        /// For testing - allows injection of a specific strategy
        /// </summary>
        internal RC2Encrypt(IEncoder encoder, IRC2Strategy strategy) : base(encoder)
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

        public override byte[] GenerateKey()
        {
            byte[] key = new byte[16]; // 128 bits
            RandomNumberGenerator.Fill(key);
            return key;
        }
    }
}
