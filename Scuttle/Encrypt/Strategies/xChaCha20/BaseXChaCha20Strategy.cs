using Scuttle.Encrypt.BernSteinCore;
using Scuttle.Helpers;

namespace Scuttle.Encrypt.Strategies.XChaCha20
{
    /// <summary>
    /// Base abstract strategy for XChaCha20 implementations that provides common functionality
    /// </summary>
    internal abstract class BaseXChaCha20Strategy : IXChaCha20Strategy
    {
        // Constants
        protected const int KeySize = ChaChaConstants.KeySize;     // 256 bits
        protected const int NonceSize = ChaChaConstants.XChaCha20NonceSize;   // 192 bits for XChaCha20
        protected const int ChaChaBlockSize = ChaChaConstants.BlockSize;  // ChaCha20 block size
        protected const int TagSize = ChaChaConstants.TagSize;     // 128 bits for Poly1305
        protected const int HChaChaRounds = 20; // Rounds for HChaCha20 function

        /// <summary>
        /// The priority of this strategy (higher numbers are preferred)
        /// </summary>
        public abstract int Priority { get; }

        /// <summary>
        /// A description of this strategy for diagnostic purposes
        /// </summary>
        public abstract string Description { get; }

        /// <summary>
        /// Process data using the XChaCha20 keystream
        /// </summary>
        public void ProcessBlock(byte[] key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output)
        {
            // Validate inputs
            if ( key == null || key.Length != KeySize )
                throw new ArgumentException("Key must be 32 bytes", nameof(key));

            if ( nonce.Length != NonceSize )
                throw new ArgumentException("Nonce must be 24 bytes for XChaCha20", nameof(nonce));

            // Derive the subkey and subnonce using HChaCha20
            byte[] subkey = HChaCha20(key, nonce.Slice(0, 16));

            // Process blocks in chunks for better cache locality
            const int chunkSize = 16 * 1024; // 16KB chunks
            for ( int offset = 0; offset < input.Length; offset += chunkSize )
            {
                int currentChunkSize = Math.Min(chunkSize, input.Length - offset);
                ProcessChunk(
                    input.Slice(offset, currentChunkSize),
                    subkey,
                    nonce.Slice(16, 8),
                    output.Slice(offset, currentChunkSize)
                );
            }
        }

        /// <summary>
        /// Generate keystream for Poly1305 key or other needs
        /// </summary>
        public byte[] GenerateKeyStream(byte[] key, ReadOnlySpan<byte> nonce, int length)
        {
            byte[] keyStream = new byte[length];
            byte[] subkey = HChaCha20(key, nonce.Slice(0, 16));

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
                state[4 + i] = BitConverter.ToUInt32(subkey.AsSpan(i * 4, 4));
            }

            // Initialize counter to 0
            state[12] = 0;

            // Set nonce (the 8 bytes from the XChaCha20 nonce after the 16 bytes used for HChaCha20)
            state[13] = BitConverter.ToUInt32(nonce.Slice(16, 4));
            state[14] = BitConverter.ToUInt32(nonce.Slice(20, 4));
            state[15] = 0; // Last word is zero for XChaCha20

            GenerateKeyStreamInternal(state, keyStream);

            return keyStream;
        }

        /// <summary>
        /// Platform-specific implementation of the HChaCha20 function
        /// </summary>
        public virtual byte[] HChaCha20(byte[] key, ReadOnlySpan<byte> nonce)
        {
            // Initialize state for HChaCha20
            Span<uint> state = stackalloc uint[16];

            // Set up the state with ChaCha constants, key, and nonce
            state[0] = ChaChaConstants.StateConstants[0];
            state[1] = ChaChaConstants.StateConstants[1];
            state[2] = ChaChaConstants.StateConstants[2];
            state[3] = ChaChaConstants.StateConstants[3];

            // Copy the key into state (words 4-11)
            for ( int i = 0; i < 8; i++ )
            {
                state[4 + i] = BitConverter.ToUInt32(key.AsSpan(i * 4, 4));
            }

            // Copy nonce into state (words 12-15)
            for ( int i = 0; i < 4; i++ )
            {
                state[12 + i] = BitConverter.ToUInt32(nonce.Slice(i * 4, 4));
            }

            // Apply the ChaCha rounds
            Span<uint> workingState = stackalloc uint[16];
            state.CopyTo(workingState);

            for ( int i = 0; i < HChaChaRounds; i += 2 )
            {
                // Column rounds
                ChaChaUtils.QuarterRound(ref workingState[0], ref workingState[4], ref workingState[8], ref workingState[12]);
                ChaChaUtils.QuarterRound(ref workingState[1], ref workingState[5], ref workingState[9], ref workingState[13]);
                ChaChaUtils.QuarterRound(ref workingState[2], ref workingState[6], ref workingState[10], ref workingState[14]);
                ChaChaUtils.QuarterRound(ref workingState[3], ref workingState[7], ref workingState[11], ref workingState[15]);

                // Diagonal rounds
                ChaChaUtils.QuarterRound(ref workingState[0], ref workingState[5], ref workingState[10], ref workingState[15]);
                ChaChaUtils.QuarterRound(ref workingState[1], ref workingState[6], ref workingState[11], ref workingState[12]);
                ChaChaUtils.QuarterRound(ref workingState[2], ref workingState[7], ref workingState[8], ref workingState[13]);
                ChaChaUtils.QuarterRound(ref workingState[3], ref workingState[4], ref workingState[9], ref workingState[14]);
            }

            // Extract subkey (first 4 words and last 4 words of the state)
            byte[] subkey = new byte[32];

            EndianHelper.WriteUInt32ToBytes(workingState[0], subkey, 0);
            EndianHelper.WriteUInt32ToBytes(workingState[1], subkey, 4);
            EndianHelper.WriteUInt32ToBytes(workingState[2], subkey, 8);
            EndianHelper.WriteUInt32ToBytes(workingState[3], subkey, 12);

            EndianHelper.WriteUInt32ToBytes(workingState[12], subkey, 16);
            EndianHelper.WriteUInt32ToBytes(workingState[13], subkey, 20);
            EndianHelper.WriteUInt32ToBytes(workingState[14], subkey, 24);
            EndianHelper.WriteUInt32ToBytes(workingState[15], subkey, 28);

            return subkey;
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
