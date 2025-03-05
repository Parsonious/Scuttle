using Scuttle.Encrypt.BernSteinCore;

namespace Scuttle.Encrypt.Strategies.ChaCha20
{
    /// <summary>
    /// Base abstract strategy for ChaCha20 implementations that provides common functionality
    /// </summary>
    internal abstract class BaseChaCha20Strategy : IChaCha20Strategy
    {
        // Constants
        protected const int KeySize = ChaChaConstants.KeySize;     // 256 bits
        protected const int NonceSize = ChaChaConstants.ChaCha20NonceSize;   // 96 bits for ChaCha20
        protected const int ChaChaBlockSize = ChaChaConstants.BlockSize;  // ChaCha20 block size

        /// <summary>
        /// The priority of this strategy (higher numbers are preferred)
        /// </summary>
        public abstract int Priority { get; }

        /// <summary>
        /// A description of this strategy for diagnostic purposes
        /// </summary>
        public abstract string Description { get; }

        /// <summary>
        /// Process data using the ChaCha20 keystream
        /// </summary>
        public void ProcessBlock(byte[] key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output)
        {
            // Validate inputs
            if ( key == null || key.Length != KeySize )
                throw new ArgumentException("Key must be 32 bytes", nameof(key));

            if ( nonce.Length != NonceSize )
                throw new ArgumentException($"Nonce must be {NonceSize} bytes for ChaCha20", nameof(nonce));

            // Process blocks in chunks for better cache locality
            const int chunkSize = 16 * 1024; // 16KB chunks
            for ( int offset = 0; offset < input.Length; offset += chunkSize )
            {
                int currentChunkSize = Math.Min(chunkSize, input.Length - offset);
                ProcessChunk(
                    input.Slice(offset, currentChunkSize),
                    key,
                    nonce,
                    output.Slice(offset, currentChunkSize)
                );
            }
        }

        /// <summary>
        /// Generate keystream for Poly1305 key or other needs
        /// </summary>
        public byte[] GenerateKeyStream(byte[] key, ReadOnlySpan<byte> nonce, int length)
        {
            if ( key == null || key.Length != KeySize )
                throw new ArgumentException("Key must be 32 bytes", nameof(key));

            if ( nonce.Length != NonceSize )
                throw new ArgumentException($"Nonce must be {NonceSize} bytes for ChaCha20", nameof(nonce));

            byte[] keyStream = new byte[length];

            // Initialize state
            Span<uint> state = stackalloc uint[16];

            // Initialize constants
            state[0] = ChaChaConstants.StateConstants[0];
            state[1] = ChaChaConstants.StateConstants[1];
            state[2] = ChaChaConstants.StateConstants[2];
            state[3] = ChaChaConstants.StateConstants[3];

            // Set key
            for ( int i = 0; i < 8; i++ )
            {
                state[4 + i] = BitConverter.ToUInt32(key.AsSpan(i * 4, 4));
            }

            // Initialize counter to 0
            state[12] = 0;

            // Set nonce
            state[13] = BitConverter.ToUInt32(nonce.Slice(0, 4));
            state[14] = BitConverter.ToUInt32(nonce.Slice(4, 4));
            state[15] = BitConverter.ToUInt32(nonce.Slice(8, 4));

            GenerateKeyStreamInternal(state, keyStream);

            return keyStream;
        }

        /// <summary>
        /// Platform-specific implementation for processing a chunk of data
        /// </summary>
        protected abstract void ProcessChunk(ReadOnlySpan<byte> inputChunk, byte[] key, ReadOnlySpan<byte> nonce, Span<byte> outputChunk);

        /// <summary>
        /// Platform-specific implementation for generating keystream
        /// </summary>
        protected abstract void GenerateKeyStreamInternal(Span<uint> initialState, Span<byte> keyStream);
    }
}
