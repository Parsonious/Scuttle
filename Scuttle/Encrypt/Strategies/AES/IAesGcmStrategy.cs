namespace Scuttle.Encrypt.Strategies.AesGcm
{
    /// <summary>
    /// Strategy interface for platform-specific AES-GCM implementations
    /// </summary>
    internal interface IAesGcmStrategy
    {
        /// <summary>
        /// Encrypts data using AES-GCM
        /// </summary>
        byte[] Encrypt(byte[] data, byte[] key);

        /// <summary>
        /// Decrypts data encrypted with AES-GCM
        /// </summary>
        byte[] Decrypt(byte[] encryptedData, byte[] key);

        /// <summary>
        /// Optional parallel encryption for large data sets
        /// </summary>
        byte[] EncryptParallel(byte[] data, byte[] key);

        /// <summary>
        /// Optional parallel decryption for large data sets
        /// </summary>
        byte[] DecryptParallel(byte[] encryptedData, byte[] key);

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
