namespace Scuttle.Encrypt.Strategies.ChaCha20
{
    /// <summary>
    /// Strategy interface for platform-specific ChaCha20 implementations
    /// </summary>
    internal interface IChaCha20Strategy
    {
        /// <summary>
        /// Process the input data using a platform-specific implementation
        /// </summary>
        void ProcessBlock(byte[] key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output);

        /// <summary>
        /// Generate keystream for Poly1305 key or other needs
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
