using Scuttle.Encrypt.BernSteinCore;
using Scuttle.Helpers;

namespace Scuttle.Encrypt.Strategies.ChaCha20
{
    /// <summary>
    /// Scalar (non-SIMD) implementation of ChaCha20 for all platforms
    /// </summary>
    internal class ChaCha20ScalarStrategy : BaseChaCha20Strategy
    {
        public override int Priority => 100; // Lowest priority
        public override string Description => "Scalar Fallback Implementation";

        protected override void ProcessChunk(ReadOnlySpan<byte> inputChunk, byte[] key, ReadOnlySpan<byte> nonce, Span<byte> outputChunk)
        {
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

            int position = 0;
            Span<uint> working = stackalloc uint[16];
            Span<byte> keyStreamBlock = stackalloc byte[ChaChaBlockSize];

            while ( position < inputChunk.Length )
            {
                // Copy state to working buffer
                state.CopyTo(working);

                // Perform ChaCha20 rounds
                for ( int round = 0; round < 10; round++ )
                {
                    // Column rounds
                    ChaChaUtils.QuarterRound(ref working[0], ref working[4], ref working[8], ref working[12]);
                    ChaChaUtils.QuarterRound(ref working[1], ref working[5], ref working[9], ref working[13]);
                    ChaChaUtils.QuarterRound(ref working[2], ref working[6], ref working[10], ref working[14]);
                    ChaChaUtils.QuarterRound(ref working[3], ref working[7], ref working[11], ref working[15]);

                    // Diagonal rounds
                    ChaChaUtils.QuarterRound(ref working[0], ref working[5], ref working[10], ref working[15]);
                    ChaChaUtils.QuarterRound(ref working[1], ref working[6], ref working[11], ref working[12]);
                    ChaChaUtils.QuarterRound(ref working[2], ref working[7], ref working[8], ref working[13]);
                    ChaChaUtils.QuarterRound(ref working[3], ref working[4], ref working[9], ref working[14]);
                }

                // Add state to working state and convert to bytes
                for ( int i = 0; i < 16; i++ )
                {
                    working[i] += state[i];
                    EndianHelper.WriteUInt32ToBytes(working[i], keyStreamBlock.Slice(i * 4, 4));
                }

                // XOR with input to produce output
                int bytesToProcess = Math.Min(ChaChaBlockSize, inputChunk.Length - position);
                for ( int i = 0; i < bytesToProcess; i++ )
                {
                    outputChunk[position + i] = (byte) (inputChunk[position + i] ^ keyStreamBlock[i]);
                }

                position += bytesToProcess;
                state[12]++; // Increment counter for next block
                if ( state[12] == 0 ) // Handle overflow
                {
                    state[13]++;
                }
            }
        }

        protected override void GenerateKeyStreamInternal(Span<uint> state, Span<byte> keyStream)
        {
            int position = 0;
            Span<uint> working = stackalloc uint[16];
            Span<byte> block = stackalloc byte[ChaChaBlockSize];
            uint counter = state[12]; // Start with provided counter

            while ( position < keyStream.Length )
            {
                // Update counter for this block
                state[12] = counter++;

                // Copy state to working buffer
                state.CopyTo(working);

                // Perform ChaCha20 block function
                for ( int i = 0; i < 10; i++ )
                {
                    // Column rounds
                    ChaChaUtils.QuarterRound(ref working[0], ref working[4], ref working[8], ref working[12]);
                    ChaChaUtils.QuarterRound(ref working[1], ref working[5], ref working[9], ref working[13]);
                    ChaChaUtils.QuarterRound(ref working[2], ref working[6], ref working[10], ref working[14]);
                    ChaChaUtils.QuarterRound(ref working[3], ref working[7], ref working[11], ref working[15]);

                    // Diagonal rounds
                    ChaChaUtils.QuarterRound(ref working[0], ref working[5], ref working[10], ref working[15]);
                    ChaChaUtils.QuarterRound(ref working[1], ref working[6], ref working[11], ref working[12]);
                    ChaChaUtils.QuarterRound(ref working[2], ref working[7], ref working[8], ref working[13]);
                    ChaChaUtils.QuarterRound(ref working[3], ref working[4], ref working[9], ref working[14]);
                }

                // Add original state back to working state
                for ( int i = 0; i < 16; i++ )
                {
                    working[i] += state[i];
                }

                // Convert to bytes
                for ( int i = 0; i < 16; i++ )
                {
                    EndianHelper.WriteUInt32ToBytes(working[i], block.Slice(i * 4, 4));
                }

                // Copy to output
                int bytesToCopy = Math.Min(ChaChaBlockSize, keyStream.Length - position);
                block.Slice(0, bytesToCopy).CopyTo(keyStream.Slice(position, bytesToCopy));
                position += bytesToCopy;
            }

            // Update counter in input state
            state[12] = counter;

            // Handle overflow - increment next word if counter wrapped around
            if ( counter == 0 )
            {
                state[13]++;
            }
        }

        /// <summary>
        /// Scalar implementation is always supported
        /// </summary>
        public static bool IsSupported => true;
    }
}
