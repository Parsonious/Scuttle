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
    /// SSE2-optimized implementation of ThreeFish
    /// </summary>
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    internal class ThreeFishSse2Strategy : BaseThreeFishStrategy
    {
        public override int Priority => 200; // Medium priority (between scalar and AVX2)
        public override string Description => "SSE2 SIMD Implementation";

        public override byte[] Encrypt(byte[] data, byte[] key)
        {
            ValidateInputs(data, key);

            // Generate random tweak
            byte[] tweak = new byte[TweakSize];
            RandomNumberGenerator.Fill(tweak);

            // Calculate padding
            int paddingLength = BlockSize - (data.Length % BlockSize);
            if ( paddingLength == BlockSize ) paddingLength = 0;  // No padding needed if exact multiple

            // Create padded data array
            byte[] paddedData = new byte[data.Length + paddingLength];
            Buffer.BlockCopy(data, 0, paddedData, 0, data.Length);

            // Add padding if needed
            if ( paddingLength > 0 )
            {
                for ( int i = data.Length; i < paddedData.Length; i++ )
                {
                    paddedData[i] = (byte) paddingLength;
                }
            }

            // Process each block
            byte[] ciphertext = new byte[paddedData.Length];
            ulong[] keySchedule = GenerateKeySchedule(key, tweak);

            // Pre-allocate block buffers
            Span<byte> block = stackalloc byte[BlockSize];
            Span<byte> encryptedBlock = stackalloc byte[BlockSize];

            // Process blocks
            for ( int i = 0; i < paddedData.Length; i += BlockSize )
            {
                paddedData.AsSpan(i, BlockSize).CopyTo(block);
                EncryptBlockSse2(block, keySchedule, encryptedBlock);
                encryptedBlock.CopyTo(ciphertext.AsSpan(i, BlockSize));
            }

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

            // Decrypt data
            byte[] ciphertext = new byte[encryptedData.Length - TweakSize - 4];
            Buffer.BlockCopy(encryptedData, TweakSize + 4, ciphertext, 0, ciphertext.Length);

            byte[] decrypted = new byte[ciphertext.Length];

            // Pre-allocate block buffers
            Span<byte> block = stackalloc byte[BlockSize];
            Span<byte> decryptedBlock = stackalloc byte[BlockSize];

            // Process blocks
            for ( int i = 0; i < ciphertext.Length; i += BlockSize )
            {
                ciphertext.AsSpan(i, BlockSize).CopyTo(block);
                DecryptBlockSse2(block, keySchedule, decryptedBlock);
                decryptedBlock.CopyTo(decrypted.AsSpan(i, BlockSize));
            }

            // Remove padding and trim to original length
            byte[] result = new byte[originalLength];
            Buffer.BlockCopy(decrypted, 0, result, 0, originalLength);

            return result;
        }

        /// <summary>
        /// Encrypt a block using SSE2 optimized code
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void EncryptBlockSse2(ReadOnlySpan<byte> input, ulong[] keySchedule, Span<byte> output)
        {
            // Initialize state vectors
            Vector128<ulong>[] state = new Vector128<ulong>[4];

            // Load input data into 4 SSE2 vectors (each holding 2 ulong values)
            InitializeStateSse2(state, input);

            // Process all rounds with SSE2
            for ( int round = 0; round < 72; round += 2 )
            {
                // Apply rounds for better SSE2 utilization
                ApplyRoundsSse2(state, keySchedule, round);
            }

            // Extract final state to output
            StoreStateToOutput(state, output);
        }

        /// <summary>
        /// Decrypt a block using SSE2 optimized code
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void DecryptBlockSse2(ReadOnlySpan<byte> input, ulong[] keySchedule, Span<byte> output)
        {
            // Initialize state vectors
            Vector128<ulong>[] state = new Vector128<ulong>[4];

            // Load input data into 4 SSE2 vectors
            InitializeStateSse2(state, input);

            // Process all rounds with SSE2 in reverse
            for ( int round = 70; round >= 0; round -= 2 )
            {
                // Apply rounds in reverse for better SSE2 utilization
                ApplyRoundsInReverseSse2(state, keySchedule, round);
            }

            // Extract final state to output
            StoreStateToOutput(state, output);
        }

        /// <summary>
        /// Initialize SSE2 state vectors from input bytes
        /// </summary>
        private void InitializeStateSse2(Vector128<ulong>[] state, ReadOnlySpan<byte> input)
        {
            // Convert input bytes to ulong values with proper endianness
            Span<ulong> values = stackalloc ulong[8];
            for ( int i = 0; i < 8; i++ )
            {
                values[i] = BitConverter.ToUInt64(input.Slice(i * 8, 8));

                // Apply endianness correction if needed
                if ( !BitConverter.IsLittleEndian )
                {
                    values[i] = EndianHelper.SwapUInt64(values[i]);
                }
            }

            // Create 4 SSE2 vectors for the state (2 ulong values per vector)
            state[0] = Vector128.Create(values[0], values[1]);
            state[1] = Vector128.Create(values[2], values[3]);
            state[2] = Vector128.Create(values[4], values[5]);
            state[3] = Vector128.Create(values[6], values[7]);
        }

        /// <summary>
        /// Apply multiple rounds of ThreeFish encryption using SSE2 intrinsics
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ApplyRoundsSse2(Vector128<ulong>[] state, ulong[] keySchedule, int startRound)
        {
            for ( int r = startRound; r < startRound + 2 && r < 72; r++ )
            {
                // Add round key (load key schedule values into SSE2 vectors)
                int scheduleIndex = r % 19;
                int keyOffset = scheduleIndex * 8;

                state[0] = AddKeyToVectorSse2(state[0], keySchedule, keyOffset);
                state[1] = AddKeyToVectorSse2(state[1], keySchedule, keyOffset + 2);
                state[2] = AddKeyToVectorSse2(state[2], keySchedule, keyOffset + 4);
                state[3] = AddKeyToVectorSse2(state[3], keySchedule, keyOffset + 6);

                // Apply mix operations using SSE2 intrinsics
                int rotationIndex = r % 8 / 2;

                // Process all mix operations
                MixVectorsSse2(ref state[0], ref state[1], GetRotation(rotationIndex, 0), r % 8 == 0);
                MixVectorsSse2(ref state[2], ref state[3], GetRotation(rotationIndex, 1), r % 8 == 0);

                // Apply permutation with minimal register shuffling
                ApplyPermutationSse2(state);
            }
        }

        /// <summary>
        /// Apply multiple rounds of ThreeFish decryption in reverse using SSE2 intrinsics
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ApplyRoundsInReverseSse2(Vector128<ulong>[] state, ulong[] keySchedule, int startRound)
        {
            for ( int r = startRound + 1; r >= startRound; r-- )
            {
                // Reverse permutation with minimal register shuffling
                ApplyInversePermutationSse2(state);

                // Apply inverse mix operations
                int rotationIndex = r % 8 / 2;

                // Process all inverse mix operations
                UnmixVectorsSse2(ref state[0], ref state[1], GetRotation(rotationIndex, 0), r % 8 == 0);
                UnmixVectorsSse2(ref state[2], ref state[3], GetRotation(rotationIndex, 1), r % 8 == 0);

                // Subtract round key (using SSE2 vectors)
                int scheduleIndex = r % 19;
                int keyOffset = scheduleIndex * 8;

                state[0] = SubtractKeyFromVectorSse2(state[0], keySchedule, keyOffset);
                state[1] = SubtractKeyFromVectorSse2(state[1], keySchedule, keyOffset + 2);
                state[2] = SubtractKeyFromVectorSse2(state[2], keySchedule, keyOffset + 4);
                state[3] = SubtractKeyFromVectorSse2(state[3], keySchedule, keyOffset + 6);
            }
        }

        /// <summary>
        /// Get rotation value from appropriate rotation table based on indexes
        /// </summary>
        private int GetRotation(int roundIndex, int mixIndex)
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
        /// Add key schedule values to a Vector128 using SSE2
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private Vector128<ulong> AddKeyToVectorSse2(Vector128<ulong> vector, ulong[] keySchedule, int offset)
        {
            // Create a Vector128 from two consecutive key schedule values
            Vector128<ulong> keyVector = Vector128.Create(
                keySchedule[offset],
                keySchedule[offset + 1]
            );

            // Use SSE2 to add 64-bit integers
            return Sse2.Add(vector.AsInt64(), keyVector.AsInt64()).AsUInt64();
        }

        /// <summary>
        /// Subtract key schedule values from a Vector128 using SSE2
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private Vector128<ulong> SubtractKeyFromVectorSse2(Vector128<ulong> vector, ulong[] keySchedule, int offset)
        {
            // Create a Vector128 from two consecutive key schedule values
            Vector128<ulong> keyVector = Vector128.Create(
                keySchedule[offset],
                keySchedule[offset + 1]
            );

            // Use SSE2 to subtract 64-bit integers
            return Sse2.Subtract(vector.AsInt64(), keyVector.AsInt64()).AsUInt64();
        }

        /// <summary>
        /// Apply the mix function to a pair of SSE2 vectors
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void MixVectorsSse2(ref Vector128<ulong> v0, ref Vector128<ulong> v1, int rotation, bool firstRound)
        {
            if ( firstRound )
            {
                // Add v1 to v0
                v0 = Sse2.Add(v0.AsInt64(), v1.AsInt64()).AsUInt64();

                // Rotate v1 left by rotation bits
                Vector128<ulong> rotatedV1 = VectorRotateLeft64Sse2(v1, rotation);

                // XOR rotated v1 with v0
                v1 = Sse2.Xor(rotatedV1, v0);
            }
            else
            {
                // Rotate v1 left by rotation bits
                v1 = VectorRotateLeft64Sse2(v1, rotation);

                // Add v1 to v0
                v0 = Sse2.Add(v0.AsInt64(), v1.AsInt64()).AsUInt64();

                // XOR v1 with v0
                v1 = Sse2.Xor(v1, v0);
            }
        }

        /// <summary>
        /// Apply the inverse mix function to a pair of SSE2 vectors
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void UnmixVectorsSse2(ref Vector128<ulong> v0, ref Vector128<ulong> v1, int rotation, bool firstRound)
        {
            if ( firstRound )
            {
                // XOR v1 with v0
                v1 = Sse2.Xor(v1, v0);

                // Rotate v1 right by rotation bits
                v1 = VectorRotateRight64Sse2(v1, rotation);

                // Subtract v1 from v0
                v0 = Sse2.Subtract(v0.AsInt64(), v1.AsInt64()).AsUInt64();
            }
            else
            {
                // XOR v1 with v0
                v1 = Sse2.Xor(v1, v0);

                // Subtract v1 from v0
                v0 = Sse2.Subtract(v0.AsInt64(), v1.AsInt64()).AsUInt64();

                // Rotate v1 right by rotation bits
                v1 = VectorRotateRight64Sse2(v1, rotation);
            }
        }

        /// <summary>
        /// Apply permutation to state vectors using SSE2 shuffles
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ApplyPermutationSse2(Vector128<ulong>[] state)
        {
            // Permutation is {0, 3, 2, 1} - rearranging vectors based on permutation pattern
            // Save original state for permutation
            Vector128<ulong> temp0 = state[0];
            Vector128<ulong> temp1 = state[1];
            Vector128<ulong> temp2 = state[2];
            Vector128<ulong> temp3 = state[3];

            // Apply permutation based on original Permutation array: {0, 3, 2, 1}
            // Map values from sources based on permutation indices
            state[0] = temp0;                // 0 stays at 0
            state[1] = temp3;                // 3 goes to 1
            state[2] = temp2;                // 2 stays at 2 
            state[3] = temp1;                // 1 goes to 3
        }

        /// <summary>
        /// Apply inverse permutation to state vectors using SSE2 shuffles
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ApplyInversePermutationSse2(Vector128<ulong>[] state)
        {
            // Inverse of permutation {0, 3, 2, 1} is {0, 3, 2, 1}
            // Save original state for permutation
            Vector128<ulong> temp0 = state[0];
            Vector128<ulong> temp1 = state[1];
            Vector128<ulong> temp2 = state[2];
            Vector128<ulong> temp3 = state[3];

            // Apply inverse permutation
            state[0] = temp0;                // 0 stays at 0
            state[1] = temp3;                // 3 goes to 1
            state[2] = temp2;                // 2 stays at 2
            state[3] = temp1;                // 1 goes to 3
        }

        /// <summary>
        /// Store the final state vectors to output byte array
        /// </summary>
        private void StoreStateToOutput(Vector128<ulong>[] state, Span<byte> output)
        {
            // Extract values from SSE2 vectors to temporary buffer
            Span<ulong> values = stackalloc ulong[8];

            // Extract from vectors (2 values per vector)
            values[0] = state[0].GetElement(0);
            values[1] = state[0].GetElement(1);
            values[2] = state[1].GetElement(0);
            values[3] = state[1].GetElement(1);
            values[4] = state[2].GetElement(0);
            values[5] = state[2].GetElement(1);
            values[6] = state[3].GetElement(0);
            values[7] = state[3].GetElement(1);

            // Convert values to bytes with proper endianness
            for ( int i = 0; i < 8; i++ )
            {
                ulong value = values[i];

                // Apply endianness correction if needed
                if ( !BitConverter.IsLittleEndian )
                {
                    value = EndianHelper.SwapUInt64(value);
                }

                BitConverter.TryWriteBytes(output.Slice(i * 8, 8), value);
            }
        }

        /// <summary>
        /// Rotate a vector of 64-bit integers left by the specified number of bits using SSE2
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<ulong> VectorRotateLeft64Sse2(Vector128<ulong> value, int rotation)
        {
            // SSE2 doesn't have a direct rotate operation for 64-bit integers
            // So we implement it using shifts and OR
            return Sse2.Xor(
                Sse2.ShiftLeftLogical(value.AsUInt64(), (byte) rotation),
                Sse2.ShiftRightLogical(value.AsUInt64(), (byte) (64 - rotation))
            );
        }

        /// <summary>
        /// Rotate a vector of 64-bit integers right by the specified number of bits using SSE2
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<ulong> VectorRotateRight64Sse2(Vector128<ulong> value, int rotation)
        {
            // Implement right rotation using shifts and OR
            return Sse2.Xor(
                Sse2.ShiftRightLogical(value.AsUInt64(), (byte) rotation),
                Sse2.ShiftLeftLogical(value.AsUInt64(), (byte) (64 - rotation))
            );
        }

        /// <summary>
        /// Process a batch of blocks in parallel when possible to maximize throughput
        /// </summary>
        public void ProcessBlocksBatch(ReadOnlySpan<byte> input, ulong[] keySchedule, Span<byte> output, bool encrypt)
        {
            // Process blocks in batches
            int blockCount = input.Length / BlockSize;

            // Process each block individually as SSE2 already handles 2 ulongs at once
            // For true multi-block processing, we would need AVX2 or better
            for ( int i = 0; i < blockCount; i++ )
            {
                int offset = i * BlockSize;
                if ( encrypt )
                {
                    EncryptBlockSse2(
                        input.Slice(offset, BlockSize),
                        keySchedule,
                        output.Slice(offset, BlockSize));
                }
                else
                {
                    DecryptBlockSse2(
                        input.Slice(offset, BlockSize),
                        keySchedule,
                        output.Slice(offset, BlockSize));
                }
            }
        }

        /// <summary>
        /// Check if SSE2 is supported on the current hardware
        /// </summary>
        public static bool IsSupported => Sse2.IsSupported;
    }
}
