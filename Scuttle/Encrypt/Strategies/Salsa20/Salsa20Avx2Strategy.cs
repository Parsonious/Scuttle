// File: Scuttle/Encrypt/Strategies/Salsa20/Salsa20Avx2Strategy.cs
using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Versioning;
using Scuttle.Encrypt.BernsteinCore;
using Scuttle.Helpers;

namespace Scuttle.Encrypt.Strategies.Salsa20
{
    /// <summary>
    /// AVX2-optimized implementation of Salsa20 that processes two blocks in parallel
    /// </summary>
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    internal class Salsa20Avx2Strategy : BaseSalsa20Strategy
    {
        public override int Priority => 300; // Highest priority
        public override string Description => "AVX2 SIMD Implementation (2x parallelism)";

        protected override void ProcessChunk(ReadOnlySpan<byte> inputChunk, Span<uint> initialState, Span<byte> outputChunk)
        {
            int position = 0;
            uint counter = initialState[8]; // Use the counter from the state

            // We can process two 64-byte blocks at once with AVX2
            byte[] blockBytes = ArrayPool<byte>.Shared.Rent(128); // 2 * BlockSize

            // Fix #7: Move stackalloc outside the loop to prevent stack overflow warning
            Span<uint> blockState = stackalloc uint[16];

            try
            {
                // Process pairs of blocks as long as we have at least 1 full block to process
                while ( position + 64 <= inputChunk.Length )
                {
                    // Make a copy of the state for these blocks
                    initialState.CopyTo(blockState);

                    // Set the counter for this block pair
                    blockState[8] = counter;

                    // Process two blocks at once using AVX2
                    ProcessTwoBlocksAvx2(blockState, blockBytes, counter);

                    // XOR the first block with input
                    VectorOperations.ApplyXorSse2(
                        inputChunk.Slice(position, Math.Min(64, inputChunk.Length - position)),
                        blockBytes.AsSpan(0, 64),
                        outputChunk.Slice(position, Math.Min(64, inputChunk.Length - position)));
                    position += 64;

                    // XOR the second block if we have enough input remaining
                    if ( position < inputChunk.Length )
                    {
                        int remaining = Math.Min(64, inputChunk.Length - position);
                        VectorOperations.ApplyXorSse2(
                            inputChunk.Slice(position, remaining),
                            blockBytes.AsSpan(64, remaining),
                            outputChunk.Slice(position, remaining));
                        position += remaining;
                    }

                    // Update counter
                    counter += 2;
                    if ( counter < 2 ) // Handle overflow
                        initialState[9]++;
                }

                // Handle remaining data (less than a full block)
                if ( position < inputChunk.Length )
                {
                    // Make a copy of the state for this block
                    initialState.CopyTo(blockState);

                    // Set the counter for this block
                    blockState[8] = counter++;
                    if ( counter == 0 ) blockState[9]++; // Handle overflow

                    // Process the last block using SSE2 (simpler for partial block)
                    Vector128<uint>[] state = new Vector128<uint>[4];
                    state[0] = Vector128.Create(blockState[0], blockState[1], blockState[2], blockState[3]);
                    state[1] = Vector128.Create(blockState[4], blockState[5], blockState[6], blockState[7]);
                    state[2] = Vector128.Create(blockState[8], blockState[9], blockState[10], blockState[11]);
                    state[3] = Vector128.Create(blockState[12], blockState[13], blockState[14], blockState[15]);

                    // Create working copy
                    Vector128<uint>[] working = new Vector128<uint>[4];
                    state.CopyTo(working, 0);

                    // Apply Salsa20 rounds
                    for ( int i = 0; i < 10; i++ )
                    {
                        SalsaQuarterRoundSse2(ref working[0], ref working[1], ref working[2], ref working[3]);
                        SalsaQuarterRoundSse2(ref working[1], ref working[2], ref working[3], ref working[0]);
                    }

                    // Add original state
                    working[0] = Sse2.Add(working[0], state[0]);
                    working[1] = Sse2.Add(working[1], state[1]);
                    working[2] = Sse2.Add(working[2], state[2]);
                    working[3] = Sse2.Add(working[3], state[3]);

                    // Store to temporary buffer
                    VectorOperations.StoreVector128(working[0], blockBytes.AsSpan(0));
                    VectorOperations.StoreVector128(working[1], blockBytes.AsSpan(16));
                    VectorOperations.StoreVector128(working[2], blockBytes.AsSpan(32));
                    VectorOperations.StoreVector128(working[3], blockBytes.AsSpan(48));

                    // XOR with input to produce output
                    int bytesToProcess = inputChunk.Length - position;
                    VectorOperations.ApplyXorSse2(
                        inputChunk.Slice(position, bytesToProcess),
                        blockBytes.AsSpan(0, bytesToProcess),
                        outputChunk.Slice(position, bytesToProcess));
                }

                // Update the counter in the original state
                initialState[8] = counter;
                if ( counter == 0 ) initialState[9]++;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(blockBytes);
            }
        }

        /// <summary>
        /// Process two Salsa20 blocks simultaneously using AVX2 instructions
        /// </summary>
        private void ProcessTwoBlocksAvx2(Span<uint> state, byte[] output, uint counter)
        {
            // Create the state for the two blocks
            Vector256<uint>[] vstate = new Vector256<uint>[4];

            // First block has counter, second block has counter+1
            Span<uint> state2 = stackalloc uint[16];
            state.CopyTo(state2);
            state2[8] = counter + 1; // Increment counter for second block

            // Interleave the state for the two blocks into AVX2 registers
            vstate[0] = Vector256.Create(
                state[0], state[1], state[2], state[3],
                state2[0], state2[1], state2[2], state2[3]);

            vstate[1] = Vector256.Create(
                state[4], state[5], state[6], state[7],
                state2[4], state2[5], state2[6], state2[7]);

            vstate[2] = Vector256.Create(
                state[8], state[9], state[10], state[11],
                state2[8], state2[9], state2[10], state2[11]);

            vstate[3] = Vector256.Create(
                state[12], state[13], state[14], state[15],
                state2[12], state2[13], state2[14], state2[15]);

            // Create working copy
            Vector256<uint>[] x = new Vector256<uint>[4];
            vstate.CopyTo(x, 0);

            // Main loop - 10 iterations of the double round
            for ( int i = 0; i < 10; i++ )
            {
                // Column rounds
                SalsaQuarterRoundAvx2(ref x[0], ref x[1], ref x[2], ref x[3]);

                // Diagonal rounds
                // Note: AVX2 doesn't have efficient rotation across lanes,
                // so we implement the usual diagonal pattern using permutes and rotations

                // Fix issues #1-#6: Add AsInt32() and AsUInt32() conversions for PermuteVar8x32
                x[1] = Avx2.PermuteVar8x32(x[1].AsInt32(), Vector256.Create(1, 2, 3, 0, 5, 6, 7, 4)).AsUInt32();
                x[2] = Avx2.PermuteVar8x32(x[2].AsInt32(), Vector256.Create(2, 3, 0, 1, 6, 7, 4, 5)).AsUInt32();
                x[3] = Avx2.PermuteVar8x32(x[3].AsInt32(), Vector256.Create(3, 0, 1, 2, 7, 4, 5, 6)).AsUInt32();

                SalsaQuarterRoundAvx2(ref x[0], ref x[1], ref x[2], ref x[3]);

                // Restore original positions
                x[1] = Avx2.PermuteVar8x32(x[1].AsInt32(), Vector256.Create(3, 0, 1, 2, 7, 4, 5, 6)).AsUInt32();
                x[2] = Avx2.PermuteVar8x32(x[2].AsInt32(), Vector256.Create(2, 3, 0, 1, 6, 7, 4, 5)).AsUInt32();
                x[3] = Avx2.PermuteVar8x32(x[3].AsInt32(), Vector256.Create(1, 2, 3, 0, 5, 6, 7, 4)).AsUInt32();
            }

            // Add initial state back to working state
            x[0] = Avx2.Add(x[0], vstate[0]);
            x[1] = Avx2.Add(x[1], vstate[1]);
            x[2] = Avx2.Add(x[2], vstate[2]);
            x[3] = Avx2.Add(x[3], vstate[3]);

            // We need to deinterleave the blocks and store them sequentially
            StoreDeinterleavedBlocks(x, output);
        }

        /// <summary>
        /// Performs a quarter round operation on four 256-bit vectors, applying the 
        /// Salsa20 quarter round to 8 sets of 4 uint32 values in parallel
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void SalsaQuarterRoundAvx2(
            ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
        {
            // b ^= RotateLeft((a + d), 7);
            var temp = Avx2.Add(a, d);
            temp = Avx2.Or(
                Avx2.ShiftLeftLogical(temp, 7),
                Avx2.ShiftRightLogical(temp, 32 - 7));
            b = Avx2.Xor(b, temp);

            // c ^= RotateLeft((b + a), 9);
            temp = Avx2.Add(b, a);
            temp = Avx2.Or(
                Avx2.ShiftLeftLogical(temp, 9),
                Avx2.ShiftRightLogical(temp, 32 - 9));
            c = Avx2.Xor(c, temp);

            // d ^= RotateLeft((c + b), 13);
            temp = Avx2.Add(c, b);
            temp = Avx2.Or(
                Avx2.ShiftLeftLogical(temp, 13),
                Avx2.ShiftRightLogical(temp, 32 - 13));
            d = Avx2.Xor(d, temp);

            // a ^= RotateLeft((d + c), 18);
            temp = Avx2.Add(d, c);
            temp = Avx2.Or(
                Avx2.ShiftLeftLogical(temp, 18),
                Avx2.ShiftRightLogical(temp, 32 - 18));
            a = Avx2.Xor(a, temp);
        }

        /// <summary>
        /// Store two interleaved Salsa20 blocks from AVX2 registers into sequential bytes
        /// </summary>
        private static void StoreDeinterleavedBlocks(Vector256<uint>[] x, byte[] output)
        {
            // Extract first block (first 4 lanes of each vector)
            Span<uint> block1 = stackalloc uint[16];
            block1[0] = x[0].GetElement(0);
            block1[1] = x[0].GetElement(1);
            block1[2] = x[0].GetElement(2);
            block1[3] = x[0].GetElement(3);
            block1[4] = x[1].GetElement(0);
            block1[5] = x[1].GetElement(1);
            block1[6] = x[1].GetElement(2);
            block1[7] = x[1].GetElement(3);
            block1[8] = x[2].GetElement(0);
            block1[9] = x[2].GetElement(1);
            block1[10] = x[2].GetElement(2);
            block1[11] = x[2].GetElement(3);
            block1[12] = x[3].GetElement(0);
            block1[13] = x[3].GetElement(1);
            block1[14] = x[3].GetElement(2);
            block1[15] = x[3].GetElement(3);

            // Extract second block (last 4 lanes of each vector)
            Span<uint> block2 = stackalloc uint[16];
            block2[0] = x[0].GetElement(4);
            block2[1] = x[0].GetElement(5);
            block2[2] = x[0].GetElement(6);
            block2[3] = x[0].GetElement(7);
            block2[4] = x[1].GetElement(4);
            block2[5] = x[1].GetElement(5);
            block2[6] = x[1].GetElement(6);
            block2[7] = x[1].GetElement(7);
            block2[8] = x[2].GetElement(4);
            block2[9] = x[2].GetElement(5);
            block2[10] = x[2].GetElement(6);
            block2[11] = x[2].GetElement(7);
            block2[12] = x[3].GetElement(4);
            block2[13] = x[3].GetElement(5);
            block2[14] = x[3].GetElement(6);
            block2[15] = x[3].GetElement(7);

            // Store blocks sequentially with proper endianness handling
            for ( int i = 0; i < 16; i++ )
            {
                EndianHelper.WriteUInt32ToBytes(block1[i], output.AsSpan(i * 4, 4));
                EndianHelper.WriteUInt32ToBytes(block2[i], output.AsSpan(64 + i * 4, 4));
            }
        }

        /// <summary>
        /// SSE2 quarter round implementation for processing the final partial block
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void SalsaQuarterRoundSse2(ref Vector128<uint> a, ref Vector128<uint> b,
            ref Vector128<uint> c, ref Vector128<uint> d)
        {
            // Implementation using SSE2 intrinsics
            var temp = Sse2.Add(a, d);
            temp = Sse2.Or(Sse2.ShiftLeftLogical(temp, 7), Sse2.ShiftRightLogical(temp, 32 - 7));
            b = Sse2.Xor(b, temp);

            temp = Sse2.Add(b, a);
            temp = Sse2.Or(Sse2.ShiftLeftLogical(temp, 9), Sse2.ShiftRightLogical(temp, 32 - 9));
            c = Sse2.Xor(c, temp);

            temp = Sse2.Add(c, b);
            temp = Sse2.Or(Sse2.ShiftLeftLogical(temp, 13), Sse2.ShiftRightLogical(temp, 32 - 13));
            d = Sse2.Xor(d, temp);

            temp = Sse2.Add(d, c);
            temp = Sse2.Or(Sse2.ShiftLeftLogical(temp, 18), Sse2.ShiftRightLogical(temp, 32 - 18));
            a = Sse2.Xor(a, temp);
        }

        /// <summary>
        /// Check if AVX2 is supported on the current hardware
        /// </summary>
        public static bool IsSupported => Avx2.IsSupported;
    }
}
