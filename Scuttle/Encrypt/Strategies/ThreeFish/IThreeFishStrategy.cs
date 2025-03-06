namespace Scuttle.Encrypt.Strategies.ThreeFish
{
    /// <summary>
    /// Strategy interface for platform-specific ThreeFish implementations
    /// </summary>
    internal interface IThreeFishStrategy
    {
        /// <summary>
        /// Encrypts data using ThreeFish
        /// </summary>
        byte[] Encrypt(byte[] data, byte[] key);

        /// <summary>
        /// Decrypts data encrypted with ThreeFish
        /// </summary>
        byte[] Decrypt(byte[] encryptedData, byte[] key);

        /// <summary>
        /// Gets the priority of this strategy (higher = better)
        /// </summary>
        int Priority { get; }

        /// <summary>
        /// Gets a description of this strategy for diagnostics
        /// </summary>
        string Description { get; }
    }
}
