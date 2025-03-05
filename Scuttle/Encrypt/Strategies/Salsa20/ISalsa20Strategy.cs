namespace Scuttle.Encrypt.Strategies.Salsa20
{
    /// <summary>
    /// Strategy interface for platform-specific Salsa20 implementations
    /// </summary>
    internal interface ISalsa20Strategy
    {
        /// <summary>
        /// Process the input data using a platform-specific implementation
        /// </summary>
        void ProcessBlock(byte[] key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output);

        /// <summary>
        /// Gets the priority of this strategy (higher = better)
        /// </summary>
        int Priority { get; }

        /// <summary>
        /// Gets a description of the strategy for diagnostics
        /// </summary>
        string Description { get; }
    }
}
