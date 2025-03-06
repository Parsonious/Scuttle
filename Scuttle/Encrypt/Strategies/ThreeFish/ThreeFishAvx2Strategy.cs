using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Scuttle.Helpers;

namespace Scuttle.Encrypt.Strategies.ThreeFish
{
    /// <summary>
    /// Fully AVX2-optimized implementation of ThreeFish
    /// </summary>
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    internal class ThreeFishAvx2Strategy : BaseThreeFishStrategy
    {
        public override int Priority => 300; // Highest priority
        public override string Description => "AVX2 SIMD Implementation (fully optimized)";
        // Cache these values for optimal AVX2 performance
        // Pre-calculated constants to avoid repeated calculations
        private static readonly byte[] _permutationControls = [ 0b_10_11_00_01 ];
        public override byte[] Encrypt(byte[] data, byte[] key)
        {
            ValidateInputs(data, key);

            // Generate random tweak
            byte[] tweak = new byte[TweakSize];
            RandomNumberGenerator.Fill(tweak);

            // Calculate padding
            int paddingLength = BlockSize - (data.Length % BlockSize);
            paddingLength = paddingLength == BlockSize ? 0 : paddingLength;  // No padding needed if exact multiple

            // Create padded data array
            byte[] paddedData = new byte[data.Length + paddingLength];
            Buffer.BlockCopy(data, 0, paddedData, 0, data.Length);

            // Add padding if needed
            if ( paddingLength > 0 )
            {
                // Use a single value for all padding bytes
                byte paddingValue = (byte) paddingLength;
                for ( int i = data.Length; i < paddedData.Length; i++ )
                {
                    paddedData[i] = paddingValue;
                }
            }

            // Process each block
            byte[] ciphertext = new byte[paddedData.Length];
            ulong[] keySchedule = GenerateKeySchedule(key, tweak);
            
            // Precompute key vectors for all blocks to avoid regeneration
            Vector256<ulong>[] keyVectors = CreateKeyVectorsOptimized(keySchedule);

            EncryptBlocksOptimized(paddedData, keyVectors, ciphertext);

            // Combine tweak, original length, and ciphertext
            byte[] result = new byte[TweakSize + sizeof(int) + ciphertext.Length];
            Buffer.BlockCopy(tweak, 0, result, 0, TweakSize);
            Buffer.BlockCopy(BitConverter.GetBytes(data.Length), 0, result, TweakSize, sizeof(int));
            Buffer.BlockCopy(ciphertext, 0, result, TweakSize + sizeof(int), ciphertext.Length);

            return result;
        }

        public override byte[] Decrypt(byte[] encryptedData, byte[] key)
        {
            if ( encryptedData == null || encryptedData.Length < TweakSize + 4 )
                throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));

            // Extract tweak and original length
            byte[] tweak = new byte[TweakSize];
            Buffer.BlockCopy(encryptedData, 0, tweak, 0, TweakSize);
            int originalLength = BitConverter.ToInt32(encryptedData, TweakSize);

            // Generate key schedule
            ulong[] keySchedule = GenerateKeySchedule(key, tweak);

            // Precompute key vectors for all blocks to avoid regeneration
            Vector256<ulong>[] keyVectors = CreateKeyVectorsOptimized(keySchedule);

            // Extract ciphertext
            byte[] ciphertext = new byte[encryptedData.Length - TweakSize - 4];
            Buffer.BlockCopy(encryptedData, TweakSize + 4, ciphertext, 0, ciphertext.Length);

            // Allocate array for decrypted data
            byte[] decrypted = new byte[ciphertext.Length];

            // Use optimized decryption for all inputs
            DecryptBlocksOptimized(ciphertext, keyVectors, decrypted);

            // Remove padding and trim to original length
            byte[] result = new byte[originalLength];
            Buffer.BlockCopy(decrypted, 0, result, 0, originalLength);

            return result;
        }

        /// <summary>
        /// Process multiple blocks in a cache-friendly manner using optimized AVX2 instructions
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void EncryptBlocksOptimized(ReadOnlySpan<byte> input, Vector256<ulong>[] keyVectors, Span<byte> output)
        {
            // Determine block count
            int blockCount = input.Length / BlockSize;

            // Choose processing strategy based on input size for optimal cache utilization
            if ( blockCount > 8 )
            {
                // For many blocks, use parallelism with cache-friendly batching
                // Typical CPU L1 cache is around 32KB-64KB, so aim to fit within that
                const int optimalBatchSize = 4; // 4 blocks = 256 bytes, plus key schedule fits in L1

                // Convert spans to arrays for use in parallel loop
                byte[] inputArray = input.ToArray();
                byte[] outputArray = new byte[output.Length];

                // Process in parallel batches for better throughput
                Parallel.For(0, (blockCount + optimalBatchSize - 1) / optimalBatchSize, batchIndex =>
                {
                    int startBlock = batchIndex * optimalBatchSize;
                    int endBlock = Math.Min(startBlock + optimalBatchSize, blockCount);

                    // Pre-allocate batch working memory on stack
                    Span<byte> batchOutput = stackalloc byte[BlockSize];

                    // Process each block in this batch
                    for ( int i = startBlock; i < endBlock; i++ )
                    {
                        int offset = i * BlockSize;

                        // Apply prefetching for next block's data - using array instead of Span
                        if ( i + 1 < endBlock )
                        {
                            PrefetchBlockData(new ReadOnlySpan<byte>(inputArray, (i + 1) * BlockSize, BlockSize));
                        }

                        // Process current block - using array instead of Span
                        EncryptBlockAvx2Optimized(
                            new ReadOnlySpan<byte>(inputArray, offset, BlockSize),
                            keyVectors,
                            batchOutput);

                        // Copy to temp array
                        batchOutput.CopyTo(new Span<byte>(outputArray, offset, BlockSize));
                    }
                });
                // Copy the result back to output span
                new ReadOnlySpan<byte>(outputArray).CopyTo(output);
            }
            else
            {
                // For small inputs, process sequentially
                Span<byte> tempOutput = stackalloc byte[BlockSize];

                for ( int i = 0; i < blockCount; i++ )
                {
                    int offset = i * BlockSize;

                    // Apply prefetching for next block's data
                    if ( i + 1 < blockCount )
                    {
                        PrefetchBlockData(input.Slice((i + 1) * BlockSize, BlockSize));
                    }

                    // Process current block
                    EncryptBlockAvx2Optimized(
                        input.Slice(offset, BlockSize),
                        keyVectors,
                        tempOutput);

                    // Copy to output
                    tempOutput.CopyTo(output.Slice(offset, BlockSize));
                }
            }
        }
        /// <summary>
        /// Process multiple blocks for decryption in a cache-friendly manner using optimized AVX2 instructions
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void DecryptBlocksOptimized(ReadOnlySpan<byte> input, Vector256<ulong>[] keyVectors, Span<byte> output)
        {
            // Determine block count
            int blockCount = input.Length / BlockSize;

            // Choose processing strategy based on input size for optimal cache utilization
            if ( blockCount > 8 )
            {
                // For many blocks, use parallelism with cache-friendly batching
                const int optimalBatchSize = 4; // 4 blocks = 256 bytes, fits well in L1 cache

                // Convert spans to arrays for use in parallel loop
                byte[] inputArray = input.ToArray();
                byte[] outputArray = new byte[output.Length];

                // Process in parallel batches for better throughput
                Parallel.For(0, (blockCount + optimalBatchSize - 1) / optimalBatchSize, batchIndex =>
                {
                    int startBlock = batchIndex * optimalBatchSize;
                    int endBlock = Math.Min(startBlock + optimalBatchSize, blockCount);

                    // Pre-allocate batch working memory on stack
                    Span<byte> batchOutput = stackalloc byte[BlockSize];

                    // Process each block in this batch
                    for ( int i = startBlock; i < endBlock; i++ )
                    {
                        int offset = i * BlockSize;

                        // Apply prefetching for next block's data - using array instead of Span
                        if ( i + 1 < endBlock )
                        {
                            PrefetchBlockData(new ReadOnlySpan<byte>(inputArray, (i + 1) * BlockSize, BlockSize));
                        }

                        // Process current block - using array instead of Span
                        DecryptBlockAvx2Optimized(
                            new ReadOnlySpan<byte>(inputArray, offset, BlockSize),
                            keyVectors,
                            batchOutput);

                        // Copy to temp array
                        batchOutput.CopyTo(new Span<byte>(outputArray, offset, BlockSize));
                    }
                });

                // Copy the result back to output span
                new ReadOnlySpan<byte>(outputArray).CopyTo(output);
            }
            else
            {
                // For small inputs, process sequentially
                Span<byte> tempOutput = stackalloc byte[BlockSize];

                for ( int i = 0; i < blockCount; i++ )
                {
                    int offset = i * BlockSize;

                    // Apply prefetching for next block's data
                    if ( i + 1 < blockCount )
                    {
                        PrefetchBlockData(input.Slice((i + 1) * BlockSize, BlockSize));
                    }

                    // Process current block
                    DecryptBlockAvx2Optimized(
                        input.Slice(offset, BlockSize),
                        keyVectors,
                        tempOutput);

                    // Copy to output
                    tempOutput.CopyTo(output.Slice(offset, BlockSize));
                }
            }
        }

        /// <summary>
        /// Encrypt a block using fully optimized AVX2 code path
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void EncryptBlockAvx2Optimized(ReadOnlySpan<byte> input, Vector256<ulong>[] keyVectors, Span<byte> output)
        {
            // Create state vectors for maximum AVX2 utilization
            Vector256<ulong>[] state = new Vector256<ulong>[4];

            // Load input into state vectors with optimized memory operations
            InitializeStateVectorsOptimized(state, input);

            // Process all rounds with highly optimized AVX2 operations
            // Process in batches of 8 rounds for maximum instruction-level parallelism
            for ( int round = 0; round < 72; round += 8 )
            {
                ApplyMultipleRoundsAvx2Optimized(state, keyVectors, round);
            }

            // Store state to output with minimal memory operations
            StoreStateOptimized(state, output);
        }

        /// <summary>
        /// Decrypt a block using fully optimized AVX2 code path
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void DecryptBlockAvx2Optimized(ReadOnlySpan<byte> input, Vector256<ulong>[] keyVectors, Span<byte> output)
        {
            // Create state vectors for maximum AVX2 utilization
            Vector256<ulong>[] state = new Vector256<ulong>[4];

            // Load input into state vectors with optimized memory operations
            InitializeStateVectorsOptimized(state, input);

            // Process all rounds in reverse with highly optimized AVX2 operations
            // Process in batches of 8 rounds for maximum instruction-level parallelism
            for ( int round = 64; round >= 0; round -= 8 )
            {
                ApplyMultipleRoundsInReverseAvx2Optimized(state, keyVectors, round);
            }

            // Store state to output with minimal memory operations
            StoreStateOptimized(state, output);
        }
        /// <summary>
        /// Optimized initialization of state vectors for maximum AVX2 performance
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void InitializeStateVectorsOptimized(Vector256<ulong>[] state, ReadOnlySpan<byte> input)
        {
            Span<ulong> values = stackalloc ulong[8];

            unsafe
            {
                fixed ( byte* inputPtr = input )
                {
                    // Use aligned loads when possible for better performance
                    bool isAligned = ((ulong) inputPtr & 0x1F) == 0; // Check 32-byte alignment
                    ulong* ulongPtr = (ulong*) inputPtr;

                    if ( BitConverter.IsLittleEndian )
                    {
                        if ( isAligned )
                        {
                            // Use aligned AVX2 loads for maximum throughput
                            state[0] = Avx2.LoadAlignedVector256(ulongPtr);
                            state[1] = Avx2.LoadAlignedVector256(ulongPtr + 4);
                        }
                        else
                        {
                            // Use unaligned loads when data isn't optimally aligned
                            state[0] = Avx2.LoadVector256(ulongPtr);
                            state[1] = Avx2.LoadVector256(ulongPtr + 4);
                        }
                    }
                    else
                    {
                        // For big-endian systems, manually swap bytes
                    
                        for ( int i = 0; i < 8; i++ )
                        {
                            values[i] = BitConverter.ToUInt64(input.Slice(i * 8, 8));
                            values[i] = EndianHelper.SwapUInt64(values[i]);
                        }

                        state[0] = Vector256.Create(values[0], values[1], values[2], values[3]);
                        state[1] = Vector256.Create(values[4], values[5], values[6], values[7]);
                    }

                    // Initialize remaining vectors to zero - critical for correct ThreeFish operation
                    state[2] = Vector256<ulong>.Zero;
                    state[3] = Vector256<ulong>.Zero;
                }
            }
        }
            /// <summary>
            /// Apply multiple rounds of ThreeFish encryption at once for better instruction pipelining
            /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ApplyMultipleRoundsAvx2Optimized(Vector256<ulong>[] state, Vector256<ulong>[] keyVectors, int startRound)
        {
            // Apply 8 rounds at once in forward direction
            // We're processing many rounds together to maximize instruction-level parallelism

            // Use batch processing for better CPU instruction pipelining
            for ( int r = startRound; r < startRound + 8 && r < 72; r += 4 )
            {
                // Precompute all keys and rotation values for 4 rounds at once
                int scheduleIndex1 = r % 19;
                int scheduleIndex2 = (r + 1) % 19;
                int scheduleIndex3 = (r + 2) % 19;
                int scheduleIndex4 = (r + 3) % 19;

                int rotIndex1 = r % 8 / 2;
                int rotIndex2 = (r + 1) % 8 / 2;
                int rotIndex3 = (r + 2) % 8 / 2;
                int rotIndex4 = (r + 3) % 8 / 2;

                // Get all rotation values for all 4 rounds
                int rot1 = GetRotation(rotIndex1, 0);
                int rot2 = GetRotation(rotIndex2, 0);
                int rot3 = GetRotation(rotIndex3, 0);
                int rot4 = GetRotation(rotIndex4, 0);

                // Process Round 1
                state[0] = Avx2.Add(state[0], GetKeyVector(keyVectors, scheduleIndex1, 0));
                state[1] = Avx2.Add(state[1], GetKeyVector(keyVectors, scheduleIndex1, 1));

                VectorMixFunction(ref state[0], ref state[1], rot1, r % 8 == 0);
                VectorMixFunction(ref state[2], ref state[3], rot1, r % 8 == 0);

                ApplyPermutationAvx2Optimized(state);

                // Process Round 2
                state[0] = Avx2.Add(state[0], GetKeyVector(keyVectors, scheduleIndex2, 0));
                state[1] = Avx2.Add(state[1], GetKeyVector(keyVectors, scheduleIndex2, 1));

                VectorMixFunction(ref state[0], ref state[1], rot2, (r + 1) % 8 == 0);
                VectorMixFunction(ref state[2], ref state[3], rot2, (r + 1) % 8 == 0);

                ApplyPermutationAvx2Optimized(state);

                // Process Round 3
                state[0] = Avx2.Add(state[0], GetKeyVector(keyVectors, scheduleIndex3, 0));
                state[1] = Avx2.Add(state[1], GetKeyVector(keyVectors, scheduleIndex3, 1));

                VectorMixFunction(ref state[0], ref state[1], rot3, (r + 2) % 8 == 0);
                VectorMixFunction(ref state[2], ref state[3], rot3, (r + 2) % 8 == 0);

                ApplyPermutationAvx2Optimized(state);

                // Process Round 4
                state[0] = Avx2.Add(state[0], GetKeyVector(keyVectors, scheduleIndex4, 0));
                state[1] = Avx2.Add(state[1], GetKeyVector(keyVectors, scheduleIndex4, 1));

                VectorMixFunction(ref state[0], ref state[1], rot4, (r + 3) % 8 == 0);
                VectorMixFunction(ref state[2], ref state[3], rot4, (r + 3) % 8 == 0);

                ApplyPermutationAvx2Optimized(state);
            }
        }
        /// <summary>
        /// Apply multiple rounds of ThreeFish decryption in reverse with enhanced AVX2 optimizations
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ApplyMultipleRoundsInReverseAvx2Optimized(Vector256<ulong>[] state, Vector256<ulong>[] keyVectors, int startRound)
        {
            // Apply 8 rounds at once in reverse direction
            // We're processing many rounds together to maximize instruction-level parallelism

            for ( int r = startRound + 7; r >= startRound; r -= 4 )
            {
                // Precompute all keys and rotation values for 4 rounds at once
                int scheduleIndex1 = r % 19;
                int scheduleIndex2 = (r - 1) % 19;
                int scheduleIndex3 = (r - 2) % 19;
                int scheduleIndex4 = (r - 3) % 19;

                int rotIndex1 = r % 8 / 2;
                int rotIndex2 = (r - 1) % 8 / 2;
                int rotIndex3 = (r - 2) % 8 / 2;
                int rotIndex4 = (r - 3) % 8 / 2;

                // Get all rotation values for all 4 rounds
                int rot1 = GetRotation(rotIndex1, 0);
                int rot2 = GetRotation(rotIndex2, 0);
                int rot3 = GetRotation(rotIndex3, 0);
                int rot4 = GetRotation(rotIndex4, 0);

                // Process Round 1 (in reverse)
                ApplyInversePermutationAvx2Optimized(state);

                VectorUnmixFunction(ref state[0], ref state[1], rot1, r % 8 == 0);
                VectorUnmixFunction(ref state[2], ref state[3], rot1, r % 8 == 0);

                state[0] = Avx2.Subtract(state[0], GetKeyVector(keyVectors, scheduleIndex1, 0));
                state[1] = Avx2.Subtract(state[1], GetKeyVector(keyVectors, scheduleIndex1, 1));

                // Process Round 2 (in reverse)
                ApplyInversePermutationAvx2Optimized(state);

                VectorUnmixFunction(ref state[0], ref state[1], rot2, (r - 1) % 8 == 0);
                VectorUnmixFunction(ref state[2], ref state[3], rot2, (r - 1) % 8 == 0);

                state[0] = Avx2.Subtract(state[0], GetKeyVector(keyVectors, scheduleIndex2, 0));
                state[1] = Avx2.Subtract(state[1], GetKeyVector(keyVectors, scheduleIndex2, 1));

                // Process Round 3 (in reverse)
                ApplyInversePermutationAvx2Optimized(state);

                VectorUnmixFunction(ref state[0], ref state[1], rot3, (r - 2) % 8 == 0);
                VectorUnmixFunction(ref state[2], ref state[3], rot3, (r - 2) % 8 == 0);

                state[0] = Avx2.Subtract(state[0], GetKeyVector(keyVectors, scheduleIndex3, 0));
                state[1] = Avx2.Subtract(state[1], GetKeyVector(keyVectors, scheduleIndex3, 1));

                // Process Round 4 (in reverse)
                ApplyInversePermutationAvx2Optimized(state);

                VectorUnmixFunction(ref state[0], ref state[1], rot4, (r - 3) % 8 == 0);
                VectorUnmixFunction(ref state[2], ref state[3], rot4, (r - 3) % 8 == 0);

                state[0] = Avx2.Subtract(state[0], GetKeyVector(keyVectors, scheduleIndex4, 0));
                state[1] = Avx2.Subtract(state[1], GetKeyVector(keyVectors, scheduleIndex4, 1));
            }
        }
        /// <summary>
        /// Optimized version of permutation that reduces register pressure
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ApplyPermutationAvx2Optimized(Vector256<ulong>[] state)
        {
            // Use a constant pattern directly
            const byte permControl = 0b_10_11_00_01; // Maps to {0, 3, 2, 1}

            // First swap state[1] and state[3] - this is part of the permutation
            Vector256<ulong> temp = state[1];
            state[1] = state[3];
            state[3] = temp;

            // Then apply in-lane permutation using efficient AVX2 operations
            // This processes all 4 state vectors in parallel
            state[0] = Avx2.Permute4x64(state[0], permControl);
            state[1] = Avx2.Permute4x64(state[1], permControl);
            state[2] = Avx2.Permute4x64(state[2], permControl);
            state[3] = Avx2.Permute4x64(state[3], permControl);
        }
        /// <summary>
        /// Optimized version of inverse permutation that reduces register pressure
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ApplyInversePermutationAvx2Optimized(Vector256<ulong>[] state)
        {
            // For ThreeFish permutation [0,3,2,1], the inverse is the same
            const byte permControl = 0b_10_11_00_01;

            // First swap state[1] and state[3] - this is part of the permutation
            Vector256<ulong> temp = state[1];
            state[1] = state[3];
            state[3] = temp;

            // Then apply in-lane permutation using efficient AVX2 operations
            state[0] = Avx2.Permute4x64(state[0], permControl);
            state[1] = Avx2.Permute4x64(state[1], permControl);
            state[2] = Avx2.Permute4x64(state[2], permControl);
            state[3] = Avx2.Permute4x64(state[3], permControl);
        }
        /// <summary>
        /// Store state to output with optimal memory operations
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void StoreStateOptimized(Vector256<ulong>[] state, Span<byte> output)
        {
            unsafe
            {
                fixed ( byte* outputPtr = output )
                {
                    if ( BitConverter.IsLittleEndian )
                    {
                        // For little-endian systems, use direct AVX2 stores for maximum performance
                        // This is much faster than element-by-element extraction
                        Avx2.Store(outputPtr, state[0].AsByte());
                        Avx2.Store(outputPtr + 32, state[1].AsByte());
                    }
                    else
                    {
                        // For big-endian systems, we need to swap the bytes
                        ulong* outputUlongPtr = (ulong*) outputPtr;

                        // Process all 8 values with minimal local variables
                        for ( int i = 0; i < 4; i++ )
                        {
                            outputUlongPtr[i] = EndianHelper.SwapUInt64(state[0].GetElement(i));
                            outputUlongPtr[i + 4] = EndianHelper.SwapUInt64(state[1].GetElement(i));
                        }
                    }
                }
            }
        }
        /// <summary>
        /// Store the final state vectors to output byte array with minimal memory operations
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void StoreStateToOutputOptimized(Vector256<ulong>[] state, Span<byte> output)
        {
            unsafe
            {
                fixed ( byte* outputPtr = output )
                {
                    if ( BitConverter.IsLittleEndian )
                    {
                        // Use AVX2 store operations for faster memory writes
                        Avx2.Store((outputPtr), state[0].AsByte());
                        Avx2.Store((outputPtr + 32), state[1].AsByte());
                    }
                    else
                    {
                        // For big-endian systems, handle byte swapping
                        ulong* outputUlongPtr = (ulong*) outputPtr;

                        // Extract and swap each element
                        for ( int i = 0; i < 4; i++ )
                        {
                            outputUlongPtr[i] = EndianHelper.SwapUInt64(state[0].GetElement(i));
                            outputUlongPtr[i + 4] = EndianHelper.SwapUInt64(state[1].GetElement(i));
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Creates pre-calculated key schedule offsets for faster lookup
        /// </summary>
        private static Vector256<int>[] CreateKeyOffsets()
        {
            Vector256<int>[] offsets = new Vector256<int>[19]; // For 19 key schedule iterations
            for ( int i = 0; i < 19; i++ )
            {
                offsets[i] = Vector256.Create(i * 8, i * 8 + 1, i * 8 + 2, i * 8 + 3,
                                              i * 8 + 4, i * 8 + 5, i * 8 + 6, i * 8 + 7);
            }
            return offsets;
        }

        /// <summary>
        /// Creates optimized vectorized key schedule using direct AVX2 loading when possible
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private Vector256<ulong>[] CreateKeyVectorsOptimized(ulong[] keySchedule)
        {
            int chunks = (keySchedule.Length + 3) / 4;
            Vector256<ulong>[] keyVectors = new Vector256<ulong>[chunks];
            Span<ulong> temp = stackalloc ulong[4];
            unsafe
            {
                fixed ( ulong* keyPtr = keySchedule )
                {
                    // Load directly from memory where possible for better performance
                    for ( int i = 0; i < chunks; i++ )
                    {
                        int offset = i * 4;
                        int remainingItems = Math.Min(4, keySchedule.Length - offset);

                        if ( remainingItems == 4 )
                        {
                            // Use AVX2 load instead of Vector256.Create for more efficient loading
                            keyVectors[i] = Avx2.LoadVector256(keyPtr + offset);
                        }
                        else
                        {
                            // Handle edge case for last chunk
                            
                            for ( int j = 0; j < remainingItems; j++ )
                            {
                                temp[j] = keySchedule[offset + j];
                            }
                            keyVectors[i] = Vector256.Create(temp[0], temp[1], temp[2], temp[3]);
                        }
                    }
                }
            }

            return keyVectors;
        }


        /// <summary>
        /// Initialize AVX2 state vectors from input bytes
        /// </summary>
        private void InitializeStateVectors(Vector256<ulong>[] state, ReadOnlySpan<byte> input)
        {
            Span<ulong> values = stackalloc ulong[8];
            // Use AVX2 to load and process data efficiently
            unsafe
            {
                fixed ( byte* inputPtr = input )
                {
                    // Load directly from memory when possible
                    if ( BitConverter.IsLittleEndian )
                    {
                        // Direct load from memory for little-endian systems
                        ulong* ulongPtr = (ulong*) inputPtr;

                        // Load all 8 values at once with 4 values per vector
                        state[0] = Vector256.Create(ulongPtr[0], ulongPtr[1], ulongPtr[2], ulongPtr[3]);
                        state[1] = Vector256.Create(ulongPtr[4], ulongPtr[5], ulongPtr[6], ulongPtr[7]);
                    }
                    else
                    {
                        // For big-endian systems, need to swap byte order

                        for ( int i = 0; i < 8; i++ )
                        {
                            values[i] = BitConverter.ToUInt64(input.Slice(i * 8, 8));
                            values[i] = EndianHelper.SwapUInt64(values[i]);
                        }

                        state[0] = Vector256.Create(values[0], values[1], values[2], values[3]);
                        state[1] = Vector256.Create(values[4], values[5], values[6], values[7]);
                    }

                    // Initialize remaining state vectors to zero
                    state[2] = Vector256<ulong>.Zero;
                    state[3] = Vector256<ulong>.Zero;
                }
            }
        }

        /// <summary>
        /// Apply multiple rounds of ThreeFish encryption using AVX2 intrinsics
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ApplyRoundsAvx2(Vector256<ulong>[] state, Vector256<ulong>[] keyVectors, Vector256<int>[] keyOffsets, int startRound)
        {
            for ( int r = startRound; r < startRound + 4 && r < 72; r++ )
            {
                // Add round key - utilize the entire state array (all 4 vectors)
                int scheduleIndex = r % 19;

                // Use more efficient gather operations with keyOffsets for vectorized key loading
                Vector256<int> offsets = keyOffsets[scheduleIndex];

                // Process all 4 state vectors, not just 2
                state[0] = Avx2.Add(state[0], GetKeyVector(keyVectors, scheduleIndex, 0));
                state[1] = Avx2.Add(state[1], GetKeyVector(keyVectors, scheduleIndex, 1));

                // Apply mix functions with specific rotations based on the round
                int rotationIndex = r % 8 / 2;

                // Use the VectorMixFunction for consistency and to apply mixing to all state vectors
                VectorMixFunction(ref state[0], ref state[1], GetRotation(rotationIndex, 0), r % 8 == 0);
                VectorMixFunction(ref state[2], ref state[3], GetRotation(rotationIndex, 1), r % 8 == 0);

                // Apply permutation using shuffling - optimize with AVX2 permute operations
                ApplyPermutationAvx2(state);
            }
        }

        /// <summary>
        /// Apply multiple rounds of ThreeFish decryption in reverse using AVX2 intrinsics
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ApplyRoundsInReverseAvx2(Vector256<ulong>[] state, Vector256<ulong>[] keyVectors, Vector256<int>[] keyOffsets, int startRound)
        {
            for ( int r = startRound + 3; r >= startRound; r-- )
            {
                // Apply inverse permutation
                ApplyInversePermutationAvx2(state);

                // Apply inverse mix operations
                int rotationIndex = r % 8 / 2;

                // Use the VectorUnmixFunction for consistency and apply to all state vectors
                VectorUnmixFunction(ref state[0], ref state[1], GetRotation(rotationIndex, 0), r % 8 == 0);
                VectorUnmixFunction(ref state[2], ref state[3], GetRotation(rotationIndex, 1), r % 8 == 0);

                // Subtract round key - utilize the entire state array
                int scheduleIndex = r % 19;

                // Use vectorized key lookups with offsets
                Vector256<int> offsets = keyOffsets[scheduleIndex];

                // Process all 4 state vectors
                state[0] = Avx2.Subtract(state[0], GetKeyVector(keyVectors, scheduleIndex, 0));
                state[1] = Avx2.Subtract(state[1], GetKeyVector(keyVectors, scheduleIndex, 1));
            }
        }
        /// <summary>
        /// Apply permutation to all state vectors using optimized AVX2 shuffle operations
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ApplyPermutationAvx2(Vector256<ulong>[] state)
        {
            // Use a constant pattern for the permutation
            // Pattern maps {0, 3, 2, 1}
            const byte permControl = 0b_10_11_00_01;

            // Optimize state swapping with single-operation permutations when possible
            Vector256<ulong> temp = state[1];
            state[1] = state[3]; // Move 3 to 1
            state[3] = temp;     // Move 1 to 3

            // Use AVX2 permute operations for in-place permutation of each vector
            state[0] = Avx2.Permute4x64(state[0], permControl);
            state[1] = Avx2.Permute4x64(state[1], permControl);
            state[2] = Avx2.Permute4x64(state[2], permControl);
            state[3] = Avx2.Permute4x64(state[3], permControl);
        }

        /// <summary>
        /// Apply inverse permutation to all state vectors using optimized AVX2 shuffle operations
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ApplyInversePermutationAvx2(Vector256<ulong>[] state)
        {
            // For ThreeFish, the inverse permutation is the same as the forward permutation
            // Pattern maps {0, 3, 2, 1}
            const byte permControl = 0b_10_11_00_01;

            // Optimize state swapping with single-operation permutations when possible
            Vector256<ulong> temp = state[1];
            state[1] = state[3]; // Move 3 to 1
            state[3] = temp;     // Move 1 to 3

            // Use AVX2 permute operations for in-place permutation of each vector
            state[0] = Avx2.Permute4x64(state[0], permControl);
            state[1] = Avx2.Permute4x64(state[1], permControl);
            state[2] = Avx2.Permute4x64(state[2], permControl);
            state[3] = Avx2.Permute4x64(state[3], permControl);
        }

        /// <summary>
        /// Get a key vector from the pre-processed key schedule using AVX2 gather operations
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private Vector256<ulong> GetKeyVectorOptimized(Vector256<ulong>[] keyVectors, Vector256<int> offsets)
        {
            Span<int> offsetValues = stackalloc int[8];
            // Use direct pointer-based access instead of problematic gather operation
            unsafe
            {
                fixed ( Vector256<ulong>* keyVectorsPtr = keyVectors )
                {
                    // Create a result vector manually since gather doesn't work directly with ulong
                    ulong* basePtr = (ulong*) keyVectorsPtr;
                    var result = new Vector256<ulong>();

                    // Extract offset values
                    
                    for ( int i = 0; i < 8; i++ )
                    {
                        offsetValues[i] = offsets.GetElement(i);
                    }
                    // Manually gather the values
                    ulong* resultPtr = (ulong*) &result;
                    for ( int i = 0; i < 8; i++ )
                    {
                        resultPtr[i] = basePtr[offsetValues[i] / sizeof(ulong)];
                    }

                    return result;
                }
            }
        }
        /// <summary>
        /// Get rotation value from appropriate rotation table based on indexes
        /// </summary>
        private static int GetRotation(int roundIndex, int mixIndex)
        {
            return roundIndex switch
            {
                0 => Rotation_0_0[mixIndex],
                1 => Rotation_1_0[mixIndex],
                2 => Rotation_2_0[mixIndex],
                3 => Rotation_3_0[mixIndex],
                _ => Rotation_0_0[mixIndex],// Fallback
            };
        }

        /// <summary>
        /// Get a key vector from the pre-processed key schedule
        /// </summary>
        private static Vector256<ulong> GetKeyVector(Vector256<ulong>[] keyVectors, int scheduleIndex, int vectorOffset)
        {
            int index = scheduleIndex * 2 + vectorOffset;
            if ( index < keyVectors.Length )
            {
                return keyVectors[index];
            }
            return Vector256<ulong>.Zero; // Fallback - should not happen with proper indexing
        }

        /// <summary>
        /// Store the final state vectors to output byte array
        /// </summary>
        private void StoreStateToOutput(Vector256<ulong>[] state, Span<byte> output)
        {
            unsafe
            {
                fixed ( byte* outputPtr = output )
                {
                    ulong* outputUlongPtr = (ulong*) outputPtr;

                    if ( BitConverter.IsLittleEndian )
                    {
                        // Extract directly to memory for little-endian systems
                        // Store all 8 values from the first 2 state vectors
                        outputUlongPtr[0] = state[0].GetElement(0);
                        outputUlongPtr[1] = state[0].GetElement(1);
                        outputUlongPtr[2] = state[0].GetElement(2);
                        outputUlongPtr[3] = state[0].GetElement(3);
                        outputUlongPtr[4] = state[1].GetElement(0);
                        outputUlongPtr[5] = state[1].GetElement(1);
                        outputUlongPtr[6] = state[1].GetElement(2);
                        outputUlongPtr[7] = state[1].GetElement(3);
                    }
                    else
                    {
                        // For big-endian systems, swap byte order when storing
                        Span<ulong> values =
                        [
                            state[0].GetElement(0),
                            state[0].GetElement(1),
                            state[0].GetElement(2),
                            state[0].GetElement(3),
                            state[1].GetElement(0),
                            state[1].GetElement(1),
                            state[1].GetElement(2),
                            state[1].GetElement(3),
                        ];
                        for ( int i = 0; i < 8; i++ )
                        {
                            ulong swapped = EndianHelper.SwapUInt64(values[i]);
                            BitConverter.TryWriteBytes(output.Slice(i * 8, 8), swapped);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Rotate a vector of 64-bit integers left by the specified number of bits
        /// Use unrolled implementation for common rotation values to avoid branching
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<ulong> VectorRotateLeft64(Vector256<ulong> value, int rotation)
        {
            // Instead of using variables, use constants directly for each common rotation value
            switch ( rotation )
            {
                case 1:
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 1), Avx2.ShiftRightLogical(value, 63));
                case 2:
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 2), Avx2.ShiftRightLogical(value, 62));
                case 8:
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 8), Avx2.ShiftRightLogical(value, 56));
                case 14: // From Rotation_1_0
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 14), Avx2.ShiftRightLogical(value, 50));
                case 16:
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 16), Avx2.ShiftRightLogical(value, 48));
                case 17: // From Rotation_2_0
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 17), Avx2.ShiftRightLogical(value, 47));
                case 19: // From Rotation_0_0
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 19), Avx2.ShiftRightLogical(value, 45));
                case 24:
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 24), Avx2.ShiftRightLogical(value, 40));
                case 27: // From Rotation_1_0
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 27), Avx2.ShiftRightLogical(value, 37));
                case 32:
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 32), Avx2.ShiftRightLogical(value, 32));
                case 33: // From Rotation_1_0
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 33), Avx2.ShiftRightLogical(value, 31));
                case 34: // From Rotation_3_0
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 34), Avx2.ShiftRightLogical(value, 30));
                case 36: // From Rotation_0_0 and Rotation_2_0
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 36), Avx2.ShiftRightLogical(value, 28));
                case 37: // From Rotation_0_0
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 37), Avx2.ShiftRightLogical(value, 27));
                case 39: // From Rotation_2_0 and Rotation_3_0
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 39), Avx2.ShiftRightLogical(value, 25));
                case 40:
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 40), Avx2.ShiftRightLogical(value, 24));
                case 42: // From Rotation_1_0
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 42), Avx2.ShiftRightLogical(value, 22));
                case 44: // From Rotation_3_0
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 44), Avx2.ShiftRightLogical(value, 20));
                case 46: // From Rotation_0_0
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 46), Avx2.ShiftRightLogical(value, 18));
                case 48:
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 48), Avx2.ShiftRightLogical(value, 16));
                case 49: // From Rotation_2_0
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 49), Avx2.ShiftRightLogical(value, 15));
                case 56: // From Rotation_3_0
                    return Avx2.Or(Avx2.ShiftLeftLogical(value, 56), Avx2.ShiftRightLogical(value, 8));
                default:
                    // For non-optimized cases, we have to use variable shifts
                    byte rotByte = (byte) rotation;
                    byte invRotByte = (byte) (64 - rotation);

                    return Avx2.Or(
                        Avx2.ShiftLeftLogical(value, rotByte),
                        Avx2.ShiftRightLogical(value, invRotByte)
                    );
            }
        }

        /// <summary>
        /// Rotate a vector of 64-bit integers right by the specified number of bits
        /// Use unrolled implementation for common rotation values to avoid branching
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<ulong> VectorRotateRight64(Vector256<ulong> value, int rotation)
        {
            switch ( rotation )
            {
                case 1:
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 1), Avx2.ShiftLeftLogical(value, 63));
                case 2:
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 2), Avx2.ShiftLeftLogical(value, 62));
                case 8:
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 8), Avx2.ShiftLeftLogical(value, 56));
                case 14: // From Rotation_1_0
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 14), Avx2.ShiftLeftLogical(value, 50));
                case 16:
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 16), Avx2.ShiftLeftLogical(value, 48));
                case 17: // From Rotation_2_0
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 17), Avx2.ShiftLeftLogical(value, 47));
                case 19: // From Rotation_0_0
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 19), Avx2.ShiftLeftLogical(value, 45));
                case 24:
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 24), Avx2.ShiftLeftLogical(value, 40));
                case 27: // From Rotation_1_0
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 27), Avx2.ShiftLeftLogical(value, 37));
                case 32:
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 32), Avx2.ShiftLeftLogical(value, 32));
                case 33: // From Rotation_1_0
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 33), Avx2.ShiftLeftLogical(value, 31));
                case 34: // From Rotation_3_0
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 34), Avx2.ShiftLeftLogical(value, 30));
                case 36: // From Rotation_0_0 and Rotation_2_0
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 36), Avx2.ShiftLeftLogical(value, 28));
                case 37: // From Rotation_0_0
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 37), Avx2.ShiftLeftLogical(value, 27));
                case 39: // From Rotation_2_0 and Rotation_3_0
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 39), Avx2.ShiftLeftLogical(value, 25));
                case 40:
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 40), Avx2.ShiftLeftLogical(value, 24));
                case 42: // From Rotation_1_0
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 42), Avx2.ShiftLeftLogical(value, 22));
                case 44: // From Rotation_3_0
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 44), Avx2.ShiftLeftLogical(value, 20));
                case 46: // From Rotation_0_0
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 46), Avx2.ShiftLeftLogical(value, 18));
                case 48:
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 48), Avx2.ShiftLeftLogical(value, 16));
                case 49: // From Rotation_2_0
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 49), Avx2.ShiftLeftLogical(value, 15));
                case 56: // From Rotation_3_0
                    return Avx2.Or(Avx2.ShiftRightLogical(value, 56), Avx2.ShiftLeftLogical(value, 8));
                default:
                    byte rotByte = (byte) rotation;
                    byte invRotByte = (byte) (64 - rotation);

                    return Avx2.Or(
                        Avx2.ShiftRightLogical(value, rotByte),
                        Avx2.ShiftLeftLogical(value, invRotByte)
                    );
            }
        }
        /// <summary>
        /// Provides specialized, highly optimized rotation functions for common ThreeFish rotation values
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<ulong> VectorRotateLeftSpecialized(Vector256<ulong> value, int rotation)
        {
            // Use hardcoded rotation values for the most common cases in ThreeFish
            // This eliminates variable shifts and enables better instruction scheduling
            return rotation switch
            {
                14 => Avx2.Or(
                                        Avx2.ShiftLeftLogical(value, 14),
                                        Avx2.ShiftRightLogical(value, 50)),
                17 => Avx2.Or(
                                        Avx2.ShiftLeftLogical(value, 17),
                                        Avx2.ShiftRightLogical(value, 47)),
                19 => Avx2.Or(
                                        Avx2.ShiftLeftLogical(value, 19),
                                        Avx2.ShiftRightLogical(value, 45)),
                27 => Avx2.Or(
                                        Avx2.ShiftLeftLogical(value, 27),
                                        Avx2.ShiftRightLogical(value, 37)),
                33 => Avx2.Or(
                                        Avx2.ShiftLeftLogical(value, 33),
                                        Avx2.ShiftRightLogical(value, 31)),
                34 => Avx2.Or(
                                        Avx2.ShiftLeftLogical(value, 34),
                                        Avx2.ShiftRightLogical(value, 30)),
                36 => Avx2.Or(
                                        Avx2.ShiftLeftLogical(value, 36),
                                        Avx2.ShiftRightLogical(value, 28)),
                37 => Avx2.Or(
                                        Avx2.ShiftLeftLogical(value, 37),
                                        Avx2.ShiftRightLogical(value, 27)),
                39 => Avx2.Or(
                                        Avx2.ShiftLeftLogical(value, 39),
                                        Avx2.ShiftRightLogical(value, 25)),
                42 => Avx2.Or(
                                        Avx2.ShiftLeftLogical(value, 42),
                                        Avx2.ShiftRightLogical(value, 22)),
                44 => Avx2.Or(
                                        Avx2.ShiftLeftLogical(value, 44),
                                        Avx2.ShiftRightLogical(value, 20)),
                46 => Avx2.Or(
                                        Avx2.ShiftLeftLogical(value, 46),
                                        Avx2.ShiftRightLogical(value, 18)),
                49 => Avx2.Or(
                                        Avx2.ShiftLeftLogical(value, 49),
                                        Avx2.ShiftRightLogical(value, 15)),
                56 => Avx2.Or(
                                        Avx2.ShiftLeftLogical(value, 56),
                                        Avx2.ShiftRightLogical(value, 8)),
                _ => VectorRotateLeft64(value, rotation),// Generic case falls back to the existing implementation
            };
        }

        /// <summary>
        /// Provides specialized, highly optimized right rotation functions for common ThreeFish values
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<ulong> VectorRotateRightSpecialized(Vector256<ulong> value, int rotation)
        {
            // Use hardcoded rotation values for common cases
            return rotation switch
            {
                14 => Avx2.Or(
                                        Avx2.ShiftRightLogical(value, 14),
                                        Avx2.ShiftLeftLogical(value, 50)),
                17 => Avx2.Or(
                                        Avx2.ShiftRightLogical(value, 17),
                                        Avx2.ShiftLeftLogical(value, 47)),
                19 => Avx2.Or(
                                        Avx2.ShiftRightLogical(value, 19),
                                        Avx2.ShiftLeftLogical(value, 45)),
                27 => Avx2.Or(
                                        Avx2.ShiftRightLogical(value, 27),
                                        Avx2.ShiftLeftLogical(value, 37)),
                33 => Avx2.Or(
                                        Avx2.ShiftRightLogical(value, 33),
                                        Avx2.ShiftLeftLogical(value, 31)),
                34 => Avx2.Or(
                                        Avx2.ShiftRightLogical(value, 34),
                                        Avx2.ShiftLeftLogical(value, 30)),
                36 => Avx2.Or(
                                        Avx2.ShiftRightLogical(value, 36),
                                        Avx2.ShiftLeftLogical(value, 28)),
                37 => Avx2.Or(
                                        Avx2.ShiftRightLogical(value, 37),
                                        Avx2.ShiftLeftLogical(value, 27)),
                39 => Avx2.Or(
                                        Avx2.ShiftRightLogical(value, 39),
                                        Avx2.ShiftLeftLogical(value, 25)),
                42 => Avx2.Or(
                                        Avx2.ShiftRightLogical(value, 42),
                                        Avx2.ShiftLeftLogical(value, 22)),
                44 => Avx2.Or(
                                        Avx2.ShiftRightLogical(value, 44),
                                        Avx2.ShiftLeftLogical(value, 20)),
                46 => Avx2.Or(
                                        Avx2.ShiftRightLogical(value, 46),
                                        Avx2.ShiftLeftLogical(value, 18)),
                49 => Avx2.Or(
                                        Avx2.ShiftRightLogical(value, 49),
                                        Avx2.ShiftLeftLogical(value, 15)),
                56 => Avx2.Or(
                                        Avx2.ShiftRightLogical(value, 56),
                                        Avx2.ShiftLeftLogical(value, 8)),
                _ => VectorRotateRight64(value, rotation),// Generic case falls back to the existing implementation
            };
        }

        /// <summary>
        /// Apply AVX2 optimized mix function with specialized rotation handling
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void VectorMixFunction(ref Vector256<ulong> x0, ref Vector256<ulong> x1, int rotation, bool firstRound)
        {
            // Use specialized versions to maximize AVX2 performance
            if ( firstRound )
            {
                // Pre-compute results to allow independent instructions to execute in parallel
                Vector256<ulong> sum = Avx2.Add(x0, x1);
                Vector256<ulong> rotated = VectorRotateLeftSpecialized(x1, rotation);
                Vector256<ulong> xored = Avx2.Xor(rotated, sum);

                // Final assignment
                x0 = sum;
                x1 = xored;
            }
            else
            {
                // Alternative algorithm for non-first rounds
                // Pre-compute results for better instruction parallelism
                Vector256<ulong> rotated = VectorRotateLeftSpecialized(x1, rotation);
                Vector256<ulong> sum = Avx2.Add(x0, rotated);
                Vector256<ulong> xored = Avx2.Xor(rotated, sum);

                // Final assignment
                x0 = sum;
                x1 = xored; ;
            }
        }

        /// <summary>
        /// Apply AVX2 optimized unmix function with specialized rotation handling
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void VectorUnmixFunction(ref Vector256<ulong> x0, ref Vector256<ulong> x1, int rotation, bool firstRound)
        {
            if ( firstRound )
            {
                // Pre-compute results to allow independent instructions to execute in parallel
                Vector256<ulong> xorResult = Avx2.Xor(x1, x0);
                Vector256<ulong> rotated = VectorRotateRightSpecialized(xorResult, rotation);
                Vector256<ulong> subtracted = Avx2.Subtract(x0, rotated);

                // Final assignment
                x1 = rotated;
                x0 = subtracted;
            }
            else
            {
                // Alternative algorithm for non-first rounds
                // Pre-compute results for better instruction parallelism
                Vector256<ulong> xorResult = Avx2.Xor(x1, x0);
                Vector256<ulong> subtracted = Avx2.Subtract(x0, xorResult);
                Vector256<ulong> rotated = VectorRotateRightSpecialized(xorResult, rotation);

                // Final assignment
                x1 = rotated;
                x0 = subtracted;
            }
        }

        /// <summary>
        /// Prefetch data into CPU cache for upcoming processing
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void PrefetchBlockData(ReadOnlySpan<byte> data)
        {
            // This is a hint to the CPU to prefetch data into cache
            // On .NET, prefetching has limited direct support, so we just touch the data
            unsafe
            {
                if ( data.Length >= BlockSize )
                {
                    fixed ( byte* ptr = data )
                    {
                        // Touch beginning of block (first cache line)
                        byte dummy1 = *ptr;

                        // Touch middle of block
                        byte dummy2 = *(ptr + BlockSize / 2);

                        // Touch end of block (last cache line)
                        byte dummy3 = *(ptr + BlockSize - 1);
                    }
                }
            }
        }
        /// <summary>
        /// Check if AVX2 is supported on the current hardware
        /// </summary>
        public static bool IsSupported => Avx2.IsSupported;
    }
}
