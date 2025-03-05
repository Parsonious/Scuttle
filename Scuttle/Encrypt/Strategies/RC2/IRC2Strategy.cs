namespace Scuttle.Encrypt.Strategies.RC2
{
    /// <summary>
    /// Strategy interface for platform-specific RC2 implementations
    /// </summary>
    internal interface IRC2Strategy
    {
        /// <summary>
        /// Encrypts data using RC2
        /// </summary>
        byte[] Encrypt(byte[] data, byte[] key);

        /// <summary>
        /// Decrypts data encrypted with RC2
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
