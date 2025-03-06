using System.Security.Cryptography;
using Scuttle.Base;
using Scuttle.Encrypt.Strategies.ThreeFish;
using Scuttle.Interfaces;

namespace Scuttle.Encrypt
{
    /// <summary>
    /// ThreeFish encryption implementation using the strategy factory pattern
    /// to select the optimal implementation based on hardware capabilities
    /// </summary>
    internal class ThreefishEncrypt : BaseEncryption
    {
        private readonly IThreeFishStrategy _strategy;

        /// <summary>
        /// Creates a new ThreeFish encryption instance that automatically selects
        /// the optimal implementation for the current hardware
        /// </summary>
        public ThreefishEncrypt(IEncoder encoder) : base(encoder)
        {
            _strategy = ThreeFishStrategyFactory.GetBestStrategy();
        }

        /// <summary>
        /// For testing - allows injection of a specific strategy
        /// </summary>
        internal ThreefishEncrypt(IEncoder encoder, IThreeFishStrategy strategy) : base(encoder)
        {
            _strategy = strategy;
        }

        public override byte[] GenerateKey()
        {
            byte[] key = new byte[64]; // 512 bits
            RandomNumberGenerator.Fill(key);
            return key;
        }

        public override byte[] Encrypt(byte[] data, byte[] key)
        {
            return _strategy.Encrypt(data, key);
        }

        public override byte[] Decrypt(byte[] encryptedData, byte[] key)
        {
            return _strategy.Decrypt(encryptedData, key);
        }
    }
}
