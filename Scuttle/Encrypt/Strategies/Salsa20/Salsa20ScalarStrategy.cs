// File: Scuttle/Encrypt/Strategies/Salsa20/Salsa20ScalarStrategy.cs
using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using Scuttle.Helpers;

namespace Scuttle.Encrypt.Strategies.Salsa20
{
    /// <summary>
    /// Scalar (non-SIMD) implementation of Salsa20 for all platforms
    /// </summary>
    internal class Salsa20ScalarStrategy : BaseSalsa20Strategy
    {
        public override int Priority => 100; // Lowest priority
        public override string Description => "Scalar Fallback Implementation";

        protected override void ProcessChunk(ReadOnlySpan<byte> inputChunk, Span<uint> initialState, Span<byte> outputChunk)
        {
            int position = 0;
            Span<uint> working = stackalloc uint[16];
            Span<byte> keyStreamBlock = stackalloc byte[64]; // BlockSize

            while ( position < inputChunk.Length )
            {
                // Copy state to working buffer
                initialState.CopyTo(working);

                // Perform Salsa20 rounds
                for ( int round = 0; round < 10; round++ )
                {
                    // Column rounds
                    QuarterRoundFast(ref working[0], ref working[4], ref working[8], ref working[12]);
                    QuarterRoundFast(ref working[5], ref working[9], ref working[13], ref working[1]);
                    QuarterRoundFast(ref working[10], ref working[14], ref working[2], ref working[6]);
                    QuarterRoundFast(ref working[15], ref working[3], ref working[7], ref working[11]);

                    // Row rounds
                    QuarterRoundFast(ref working[0], ref working[1], ref working[2], ref working[3]);
                    QuarterRoundFast(ref working[5], ref working[6], ref working[7], ref working[4]);
                    QuarterRoundFast(ref working[10], ref working[11], ref working[8], ref working[9]);
                    QuarterRoundFast(ref working[15], ref working[12], ref working[13], ref working[14]);
                }

                // Add state to working state and convert to bytes
                for ( int j = 0; j < 16; j++ )
                {
                    working[j] += initialState[j];
                    EndianHelper.WriteUInt32ToBytes(working[j], keyStreamBlock.Slice(j * 4, 4));
                }

                // XOR with input to produce output
                int bytesToProcess = Math.Min(64, inputChunk.Length - position);
                for ( int k = 0; k < bytesToProcess; k++ )
                {
                    outputChunk[position + k] = (byte) (inputChunk[position + k] ^ keyStreamBlock[k]);
                }

                position += bytesToProcess;
                initialState[8]++; // Increment counter for next block
                if ( initialState[8] == 0 ) // Handle overflow
                {
                    initialState[9]++;
                }
            }
        }

        // Always supported
        public static bool IsSupported => true;
    }
}
