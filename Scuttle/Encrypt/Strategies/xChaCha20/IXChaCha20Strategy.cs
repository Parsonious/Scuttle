namespace Scuttle.Encrypt.Strategies.XChaCha20
{
    /// <summary>
    /// Strategy interface for platform-specific XChaCha20 implementations
    /// </summary>
    internal interface IXChaCha20Strategy
    {
        /// <summary>
        /// Process the input data using a platform-specific implementation
        /// </summary>
        void ProcessBlock(byte[] key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output);

        /// <summary>
        /// Computes the HChaCha20 derivation function (subkey generation)
        /// </summary>
        byte[] HChaCha20(byte[] key, ReadOnlySpan<byte> nonce);

        /// <summary>
        /// Generate keystream for Poly1305 or other needs
        /// </summary>
        byte[] GenerateKeyStream(byte[] key, ReadOnlySpan<byte> nonce, int length);

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