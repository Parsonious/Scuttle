// File: Scuttle/Encrypt/Strategies/Salsa20/BaseSalsa20Strategy.cs
using System;
using System.Buffers;
using System.Numerics;
using System.Runtime.CompilerServices;
using Scuttle.Encrypt.BernsteinCore;
using Scuttle.Encrypt.BernSteinCore;

namespace Scuttle.Encrypt.Strategies.Salsa20
{
    /// <summary>
    /// Base abstract strategy for Salsa20 implementations that provides common functionality
    /// </summary>
    internal abstract class BaseSalsa20Strategy : ISalsa20Strategy
    {
        /// <summary>
        /// The priority of this strategy (higher numbers are preferred)
        /// </summary>
        public abstract int Priority { get; }

        /// <summary>
        /// A description of this strategy for diagnostic purposes
        /// </summary>
        public abstract string Description { get; }

        /// <summary>
        /// Process a block using the strategy's specific implementation
        /// </summary>
        public void ProcessBlock(byte[] key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output)
        {
            // Validate inputs
            if ( key == null || key.Length != 32 )
                throw new ArgumentException("Key must be 32 bytes", nameof(key));

            if ( nonce.Length != 8 )
                throw new ArgumentException("Nonce must be 8 bytes for Salsa20", nameof(nonce));

            // Initialize state
            Span<uint> initialState = stackalloc uint[16];
            InitializeSalsaState(initialState, key, nonce);

            // Process blocks in chunks for better cache locality
            const int chunkSize = 16 * 1024; // 16KB chunks
            for ( int offset = 0; offset < input.Length; offset += chunkSize )
            {
                int currentChunkSize = Math.Min(chunkSize, input.Length - offset);
                ProcessChunk(
                    input.Slice(offset, currentChunkSize),
                    initialState,
                    output.Slice(offset, currentChunkSize)
                );
            }
        }

        /// <summary>
        /// Platform-specific implementation for processing a chunk of data
        /// </summary>
        /// <remarks>
        /// This method is implemented by derived classes to provide platform-specific optimizations.
        /// </remarks>
        protected abstract void ProcessChunk(ReadOnlySpan<byte> inputChunk, Span<uint> initialState, Span<byte> outputChunk);

        /// <summary>
        /// Initialize the Salsa20 state with key and nonce
        /// </summary>
        protected void InitializeSalsaState(Span<uint> state, byte[] key, ReadOnlySpan<byte> nonce)
        {
            // Initialize with constants - "expand 32-byte k"
            state[0] = ChaChaConstants.StateConstants[0];
            state[5] = ChaChaConstants.StateConstants[1];
            state[10] = ChaChaConstants.StateConstants[2];
            state[15] = ChaChaConstants.StateConstants[3];

            // Load key (first half)
            state[1] = BitConverter.ToUInt32(key, 0);
            state[2] = BitConverter.ToUInt32(key, 4);
            state[3] = BitConverter.ToUInt32(key, 8);
            state[4] = BitConverter.ToUInt32(key, 12);

            // Load key (second half)
            state[11] = BitConverter.ToUInt32(key, 16);
            state[12] = BitConverter.ToUInt32(key, 20);
            state[13] = BitConverter.ToUInt32(key, 24);
            state[14] = BitConverter.ToUInt32(key, 28);

            // Counter starts at 0
            state[8] = 0;
            state[9] = 0;

            // Load nonce
            state[6] = BitConverter.ToUInt32(nonce.Slice(0, 4));
            state[7] = BitConverter.ToUInt32(nonce.Slice(4, 4));
        }

        /// <summary>
        /// Fast quarter round implementation for Salsa20
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected static void QuarterRoundFast(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            // Salsa20 uses a different mixing function than ChaCha20
            b ^= BitOperations.RotateLeft((a + d), 7);
            c ^= BitOperations.RotateLeft((b + a), 9);
            d ^= BitOperations.RotateLeft((c + b), 13);
            a ^= BitOperations.RotateLeft((d + c), 18);
        }
    }
}
