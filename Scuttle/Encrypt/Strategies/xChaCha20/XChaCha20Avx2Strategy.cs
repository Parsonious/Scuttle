using System.Buffers;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Versioning;
using Scuttle.Encrypt.BernsteinCore;
using Scuttle.Encrypt.BernSteinCore;
using Scuttle.Helpers;


namespace Scuttle.Encrypt.Strategies.XChaCha20
{
    /// <summary>
    /// AVX2-optimized implementation of XChaCha20 that processes two blocks in parallel
    /// </summary>
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    internal class XChaCha20Avx2Strategy : BaseXChaCha20Strategy
    {
        public override int Priority => 300; // Highest priority
        public override string Description => "AVX2 SIMD Implementation (2x parallelism)";

        protected override void ProcessChunk(ReadOnlySpan<byte> inputChunk, byte[] key, ReadOnlySpan<byte> nonce, Span<byte> outputChunk)
        {
            int position = 0;
            uint counter = 0;

            // We can process two 64-byte blocks at once with AVX2
            byte[] blockBytes = ArrayPool<byte>.Shared.Rent(128); // 2 * ChaChaBlockSize

            try
            {
                // Initialize state
                Span<uint> initialState = stackalloc uint[16];

                // Initialize constants
                initialState[0] = ChaChaConstants.StateConstants[0];
                initialState[1] = ChaChaConstants.StateConstants[1];
                initialState[2] = ChaChaConstants.StateConstants[2];
                initialState[3] = ChaChaConstants.StateConstants[3];

                // Set key
                for ( int i = 0; i < 8; i++ )
                {
                    initialState[4 + i] = BitConverter.ToUInt32(key.AsSpan(i * 4, 4));
                }

                // Set nonce
                initialState[13] = BitConverter.ToUInt32(nonce[..4]);
                initialState[14] = BitConverter.ToUInt32(nonce.Slice(4, 4));
                initialState[15] = 0; // Last word is zero for XChaCha20

                // Process pairs of blocks as long as we have at least 1 full block
                while ( position + ChaChaBlockSize <= inputChunk.Length )
                {
                    // Set counter for this block pair
                    initialState[12] = counter;

                    // Process two blocks at once using AVX2
                    ProcessTwoBlocksAvx2(initialState, blockBytes, counter);

                    // XOR the first block with input
                    VectorOperations.ApplyXorSse2(
                        inputChunk.Slice(position, Math.Min(ChaChaBlockSize, inputChunk.Length - position)),
                        blockBytes.AsSpan(0, ChaChaBlockSize),
                        outputChunk.Slice(position, Math.Min(ChaChaBlockSize, inputChunk.Length - position)));
                    position += ChaChaBlockSize;

                    // XOR the second block if we have enough input remaining
                    if ( position < inputChunk.Length )
                    {
                        int remaining = Math.Min(ChaChaBlockSize, inputChunk.Length - position);
                        VectorOperations.ApplyXorSse2(
                            inputChunk.Slice(position, remaining),
                            blockBytes.AsSpan(ChaChaBlockSize, remaining),
                            outputChunk.Slice(position, remaining));
                        position += remaining;
                    }

                    // Update counter
                    counter += 2;
                }

                // Handle remaining data (less than a full block)
                if ( position < inputChunk.Length )
                {
                    // Process the last block using SSE2 (simpler for partial block)
                    initialState[12] = counter;

                    // Use SSE2 for the final partial block
                    Vector128<uint>[] state =
                    [
                        Vector128.Create(initialState[0], initialState[1], initialState[2], initialState[3]),
                        Vector128.Create(initialState[4], initialState[5], initialState[6], initialState[7]),
                        Vector128.Create(initialState[8], initialState[9], initialState[10], initialState[11]),
                        Vector128.Create(initialState[12], initialState[13], initialState[14], initialState[15]),
                    ];

                    // Create working copy
                    Vector128<uint>[] working = new Vector128<uint>[4];
                    state.CopyTo(working, 0);

                    // Apply ChaCha20 rounds
                    for ( int i = 0; i < 10; i++ )
                    {
                        ChaChaUtils.ChaChaRoundSse2(ref working[0], ref working[1], ref working[2], ref working[3]);
                    }

                    // Add original state
                    working[0] = Sse2.Add(working[0], state[0]);
                    working[1] = Sse2.Add(working[1], state[1]);
                    working[2] = Sse2.Add(working[2], state[2]);
                    working[3] = Sse2.Add(working[3], state[3]);

                    // Store to buffer
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
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(blockBytes);
            }
        }

        private void ProcessTwoBlocksAvx2(Span<uint> state, byte[] output, uint counter)
        {
            // Create the state for the two blocks
            Vector256<uint>[] vstate = new Vector256<uint>[4];

            // First block has counter, second block has counter+1
            Span<uint> state2 = stackalloc uint[16];
            state.CopyTo(state2);
            state2[12] = counter + 1; // Increment counter for second block

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

            // Main loop - 10 iterations of ChaCha20 rounds
            for ( int i = 0; i < 10; i++ )
            {
                // Column rounds - Using our own implementation since it's missing from ChaChaUtils
                QuarterRoundAvx2(ref x[0], ref x[1], ref x[2], ref x[3]);

                // Diagonal rounds (with appropriate shuffling)
                // Fix: Cast to Vector256<int> for the first argument
                x[1] = Avx2.PermuteVar8x32(x[1].AsInt32(), Vector256.Create(1, 2, 3, 0, 5, 6, 7, 4)).AsUInt32();
                x[2] = Avx2.PermuteVar8x32(x[2].AsInt32(), Vector256.Create(2, 3, 0, 1, 6, 7, 4, 5)).AsUInt32();
                x[3] = Avx2.PermuteVar8x32(x[3].AsInt32(), Vector256.Create(3, 0, 1, 2, 7, 4, 5, 6)).AsUInt32();

                // Diagonal rounds - Using our own implementation 
                QuarterRoundAvx2(ref x[0], ref x[1], ref x[2], ref x[3]);

                // Restore original positions with proper type casting
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
        /// Performs a quarter round operation on four 256-bit vectors using AVX2
        /// </summary>
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
        private static void QuarterRoundAvx2(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
        {
            // b ^= RotateLeft((a + d), 7);
            var temp = Avx2.Add(a, d);
            temp = Avx2.Xor(
                Avx2.ShiftLeftLogical(temp, 7),
                Avx2.ShiftRightLogical(temp, 32 - 7));
            b = Avx2.Xor(b, temp);

            // c ^= RotateLeft((b + a), 9);
            temp = Avx2.Add(b, a);
            temp = Avx2.Xor(
                Avx2.ShiftLeftLogical(temp, 9),
                Avx2.ShiftRightLogical(temp, 32 - 9));
            c = Avx2.Xor(c, temp);

            // d ^= RotateLeft((c + b), 13);
            temp = Avx2.Add(c, b);
            temp = Avx2.Xor(
                Avx2.ShiftLeftLogical(temp, 13),
                Avx2.ShiftRightLogical(temp, 32 - 13));
            d = Avx2.Xor(d, temp);

            // a ^= RotateLeft((d + c), 18);
            temp = Avx2.Add(d, c);
            temp = Avx2.Xor(
                Avx2.ShiftLeftLogical(temp, 18),
                Avx2.ShiftRightLogical(temp, 32 - 18));
            a = Avx2.Xor(a, temp);
        }
        /// <summary>
        /// Store two interleaved ChaCha20 blocks from AVX2 registers into sequential bytes
        /// </summary>
        private static void StoreDeinterleavedBlocks(Vector256<uint>[] x, byte[] output)
        {
            // Extract first block (first 4 lanes of each vector)
            Span<uint> block1 =
            [
                x[0].GetElement(0),
                x[0].GetElement(1),
                x[0].GetElement(2),
                x[0].GetElement(3),
                x[1].GetElement(0),
                x[1].GetElement(1),
                x[1].GetElement(2),
                x[1].GetElement(3),
                x[2].GetElement(0),
                x[2].GetElement(1),
                x[2].GetElement(2),
                x[2].GetElement(3),
                x[3].GetElement(0),
                x[3].GetElement(1),
                x[3].GetElement(2),
                x[3].GetElement(3),
            ];

            // Extract second block (last 4 lanes of each vector)
            Span<uint> block2 =
            [
                x[0].GetElement(4),
                x[0].GetElement(5),
                x[0].GetElement(6),
                x[0].GetElement(7),
                x[1].GetElement(4),
                x[1].GetElement(5),
                x[1].GetElement(6),
                x[1].GetElement(7),
                x[2].GetElement(4),
                x[2].GetElement(5),
                x[2].GetElement(6),
                x[2].GetElement(7),
                x[3].GetElement(4),
                x[3].GetElement(5),
                x[3].GetElement(6),
                x[3].GetElement(7),
            ];

            // Store blocks sequentially with proper endianness handling
            for ( int i = 0; i < 16; i++ )
            {
                EndianHelper.WriteUInt32ToBytes(block1[i], output.AsSpan(i * 4, 4));
                EndianHelper.WriteUInt32ToBytes(block2[i], output.AsSpan(64 + i * 4, 4));
            }
        }

        /// <summary>
        /// Generate keystream for XChaCha20 using AVX2
        /// </summary>
        protected override void GenerateKeyStreamInternal(Span<uint> initialState, Span<byte> keyStream)
        {
            int position = 0;
            uint counter = initialState[12]; // Start with the initial counter value

            byte[] doubleBlockBytes = ArrayPool<byte>.Shared.Rent(128); // 2 * ChaChaBlockSize

            try
            {
                // Process two blocks at a time with AVX2
                while ( position + ChaChaBlockSize < keyStream.Length )
                {
                    // Process two blocks at once
                    ProcessTwoBlocksAvx2(initialState, doubleBlockBytes, counter);

                    // Copy to output
                    int bytesToCopy = Math.Min(128, keyStream.Length - position);
                    if ( bytesToCopy > ChaChaBlockSize )
                    {
                        doubleBlockBytes.AsSpan(0, ChaChaBlockSize).CopyTo(keyStream.Slice(position, ChaChaBlockSize));
                        position += ChaChaBlockSize;
                        int remainingBytes = bytesToCopy - ChaChaBlockSize;
                        doubleBlockBytes.AsSpan(ChaChaBlockSize, remainingBytes).CopyTo(keyStream.Slice(position, remainingBytes));
                        position += remainingBytes;
                    }
                    else
                    {
                        doubleBlockBytes.AsSpan(0, bytesToCopy).CopyTo(keyStream.Slice(position, bytesToCopy));
                        position += bytesToCopy;
                    }

                    // Update counter
                    counter += 2;
                    initialState[12] = counter;
                }

                // Handle any remaining bytes with SSE2 (if less than a full block remaining)
                if ( position < keyStream.Length )
                {
                    byte[] blockBytes = ArrayPool<byte>.Shared.Rent(ChaChaBlockSize);
                    try
                    {
                        // Use SSE2 for the final partial block
                        Vector128<uint>[] state =
                        [
                            Vector128.Create(initialState[0], initialState[1], initialState[2], initialState[3]),
                            Vector128.Create(initialState[4], initialState[5], initialState[6], initialState[7]),
                            Vector128.Create(initialState[8], initialState[9], initialState[10], initialState[11]),
                            Vector128.Create(counter, initialState[13], initialState[14], initialState[15]),
                        ];

                        // Create working copy
                        Vector128<uint>[] working = new Vector128<uint>[4];
                        state.CopyTo(working, 0);

                        // Apply ChaCha20 rounds
                        for ( int i = 0; i < 10; i++ )
                        {
                            ChaChaUtils.ChaChaRoundSse2(ref working[0], ref working[1], ref working[2], ref working[3]);
                        }

                        // Add original state
                        working[0] = Sse2.Add(working[0], state[0]);
                        working[1] = Sse2.Add(working[1], state[1]);
                        working[2] = Sse2.Add(working[2], state[2]);
                        working[3] = Sse2.Add(working[3], state[3]);

                        // Store to buffer
                        VectorOperations.StoreVector128(working[0], blockBytes.AsSpan(0));
                        VectorOperations.StoreVector128(working[1], blockBytes.AsSpan(16));
                        VectorOperations.StoreVector128(working[2], blockBytes.AsSpan(32));
                        VectorOperations.StoreVector128(working[3], blockBytes.AsSpan(48));

                        // Copy to output
                        int bytesToCopy = keyStream.Length - position;
                        blockBytes.AsSpan(0, bytesToCopy).CopyTo(keyStream.Slice(position, bytesToCopy));

                        // Update counter
                        initialState[12] = counter + 1;
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(blockBytes);
                    }
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(doubleBlockBytes);
            }
        }

        /// <summary>
        /// Optimized AVX2 implementation of HChaCha20
        /// </summary>
        public override byte[] HChaCha20(byte[] key, ReadOnlySpan<byte> nonce)
        {
            // Use SSE2 implementation for HChaCha20 as it's single-block operation
            // and doesn't benefit from AVX2's double-block processing

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

            // Create SSE2 vectors
            Vector128<uint>[] v =
            [
                Vector128.Create(state[0], state[1], state[2], state[3]),
                Vector128.Create(state[4], state[5], state[6], state[7]),
                Vector128.Create(state[8], state[9], state[10], state[11]),
                Vector128.Create(state[12], state[13], state[14], state[15]),
            ];

            // Apply the ChaCha rounds
            for ( int i = 0; i < 10; i++ )
            {
                // Column rounds
                ChaChaUtils.ChaChaRoundSse2(ref v[0], ref v[1], ref v[2], ref v[3]);

                // Create a copy for diagonal rounds with different element order
                Vector128<uint> t0 = v[0];
                Vector128<uint> t1 = Sse2.Shuffle(v[1], 0b00_11_10_01); // Rotate left by 1
                Vector128<uint> t2 = Sse2.Shuffle(v[2], 0b01_00_11_10); // Rotate left by 2
                Vector128<uint> t3 = Sse2.Shuffle(v[3], 0b10_01_00_11); // Rotate left by 3

                // Diagonal rounds
                ChaChaUtils.ChaChaRoundSse2(ref t0, ref t1, ref t2, ref t3);

                // Restore original order for next column round
                v[0] = t0;
                v[1] = Sse2.Shuffle(t1, 0b10_01_00_11); // Rotate right by 1
                v[2] = Sse2.Shuffle(t2, 0b01_00_11_10); // Rotate right by 2
                v[3] = Sse2.Shuffle(t3, 0b00_11_10_01); // Rotate right by 3
            }

            // Extract subkey (first 4 words and last 4 words of the state)
            byte[] subkey = new byte[32];
            Span<byte> tempBuffer = stackalloc byte[16];

            // Extract first 16 bytes
            VectorOperations.StoreVector128(v[0], tempBuffer);
            tempBuffer.CopyTo(subkey.AsSpan(0, 16));

            // Extract last 16 bytes
            VectorOperations.StoreVector128(v[3], tempBuffer);
            tempBuffer.CopyTo(subkey.AsSpan(16, 16));

            return subkey;
        }

        public static bool IsSupported => Avx2.IsSupported;
    }
}
