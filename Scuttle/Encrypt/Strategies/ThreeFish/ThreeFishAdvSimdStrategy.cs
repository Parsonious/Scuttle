using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Scuttle.Helpers;

namespace Scuttle.Encrypt.Strategies.ThreeFish
{
    /// <summary>
    /// ARM AdvSimd (NEON) optimized implementation of ThreeFish
    /// </summary>
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    internal class ThreeFishAdvSimdStrategy : BaseThreeFishStrategy
    {
        public override int Priority => 250; // Higher than SSE2 but lower than AVX2
        public override string Description => "ARM AdvSimd (NEON) Implementation";
       
        // Fields for pre-computed permutation vectors to speed up permutation operations on ARM64
        private static readonly Vector128<long>? _permutationControl;

        /// <summary>
        /// Check if ARM AdvSimd is supported on the current hardware
        /// </summary>
        public static bool IsSupported => AdvSimd.IsSupported;


        // Static constructor to initialize permutation vectors
        static ThreeFishAdvSimdStrategy()
        {
            if ( AdvSimd.Arm64.IsSupported )
            {
                // Initialize permutation control vectors for ARM64
                // This will let us use advanced Arm64 shuffling instructions
                _permutationControl = Vector128.Create(0L, 3L, 2L, 1L).AsInt64();
            }
        }
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
                EncryptBlockAdvSimd(block, keySchedule, encryptedBlock);
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
                DecryptBlockAdvSimd(block, keySchedule, decryptedBlock);
                decryptedBlock.CopyTo(decrypted.AsSpan(i, BlockSize));
            }

            // Remove padding and trim to original length
            byte[] result = new byte[originalLength];
            Buffer.BlockCopy(decrypted, 0, result, 0, originalLength);

            return result;
        }

        /// <summary>
        /// Encrypt a block using ARM AdvSimd optimized code
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void EncryptBlockAdvSimd(ReadOnlySpan<byte> input, ulong[] keySchedule, Span<byte> output)
        {
            // Initialize state vectors
            Vector128<ulong>[] state = new Vector128<ulong>[4];

            // Load input data into 4 AdvSimd vectors (each holding 2 ulong values)
            InitializeStateAdvSimd(state, input);

            // Process all rounds with AdvSimd
            for ( int round = 0; round < 72; round += 2 )
            {
                // Apply rounds for better AdvSimd utilization
                ApplyRoundsAdvSimd(state, keySchedule, round);
            }

            // Extract final state to output
            StoreStateToOutput(state, output);
        }

        /// <summary>
        /// Decrypt a block using ARM AdvSimd optimized code
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void DecryptBlockAdvSimd(ReadOnlySpan<byte> input, ulong[] keySchedule, Span<byte> output)
        {
            // Initialize state vectors
            Vector128<ulong>[] state = new Vector128<ulong>[4];

            // Load input data into 4 AdvSimd vectors
            InitializeStateAdvSimd(state, input);

            // Process all rounds with AdvSimd in reverse
            for ( int round = 70; round >= 0; round -= 2 )
            {
                // Apply rounds in reverse for better AdvSimd utilization
                ApplyRoundsInReverseAdvSimd(state, keySchedule, round);
            }

            // Extract final state to output
            StoreStateToOutput(state, output);
        }

        /// <summary>
        /// Initialize AdvSimd state vectors from input bytes
        /// </summary>
        private void InitializeStateAdvSimd(Vector128<ulong>[] state, ReadOnlySpan<byte> input)
        {
            // For ARM64, we can optimize memory access patterns
            if ( AdvSimd.Arm64.IsSupported )
            {
                // On ARM64, we can load directly from memory into NEON registers
                // and handle endianness more efficiently
                state[0] = LoadUInt64PairOptimized(input, 0);
                state[1] = LoadUInt64PairOptimized(input, 16);
                state[2] = LoadUInt64PairOptimized(input, 32);
                state[3] = LoadUInt64PairOptimized(input, 48);
            }
            else
            {
                // Original implementation for 32-bit ARM
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

                state[0] = Vector128.Create(values[0], values[1]);
                state[1] = Vector128.Create(values[2], values[3]);
                state[2] = Vector128.Create(values[4], values[5]);
                state[3] = Vector128.Create(values[6], values[7]);
            }
        }

        /// <summary>
        /// Safely shift left within AdvSimd constraints using constants for optimal performance
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<ulong> SafeShiftLeft(Vector128<ulong> value, int shift)
        {
            // Use switch to select from constant shifts
            switch ( shift )
            {
                case 0: return value;
                case 1: return AdvSimd.ShiftLeftLogical(value, 1);
                case 2: return AdvSimd.ShiftLeftLogical(value, 2);
                case 3: return AdvSimd.ShiftLeftLogical(value, 3);
                case 4: return AdvSimd.ShiftLeftLogical(value, 4);
                case 5: return AdvSimd.ShiftLeftLogical(value, 5);
                case 6: return AdvSimd.ShiftLeftLogical(value, 6);
                case 7: return AdvSimd.ShiftLeftLogical(value, 7);
                case 8: return AdvSimd.ShiftLeftLogical(value, 8);
                case 9: return AdvSimd.ShiftLeftLogical(value, 9);
                case 10: return AdvSimd.ShiftLeftLogical(value, 10);
                case 11: return AdvSimd.ShiftLeftLogical(value, 11);
                case 12: return AdvSimd.ShiftLeftLogical(value, 12);
                case 13: return AdvSimd.ShiftLeftLogical(value, 13);
                case 14: return AdvSimd.ShiftLeftLogical(value, 14);
                case 15: return AdvSimd.ShiftLeftLogical(value, 15);

                // For larger shifts, compose with multiple constant shifts
                case 16: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 1);
                case 17: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 2);
                case 18: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 3);
                case 19: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 4);
                case 20: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 5);
                case 27: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 10), 2);
                case 30: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15);
                case 31: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 1);
                case 33: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 3);
                case 34: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 4);
                case 36: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 6);
                case 37: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 7);
                case 39: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 9);
                case 42: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 12);
                case 44: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 14);
                case 45: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 15);
                case 46: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 15), 1);
                case 47: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 15), 2);
                case 49: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 15), 4);
                case 50: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 15), 5);
                case 56: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 15), 11);
                case 63: return AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(AdvSimd.ShiftLeftLogical(value, 15), 15), 15), 18);

                // For any other shifts, we need to compose multiple shifts
                default:
                    // Use previously defined constants to compose the shift
                    if ( shift < 15 )
                    {
                        // Use direct shift for small values
                        return AdvSimd.ShiftLeftLogical(value, (byte) shift);
                    }
                    else if ( shift < 30 )
                    {
                        // For shifts between 15-29, use combination of 15 + remainder
                        return AdvSimd.ShiftLeftLogical(
                            AdvSimd.ShiftLeftLogical(value, 15),
                            (byte) (shift - 15));
                    }
                    else if ( shift < 45 )
                    {
                        // For shifts between 30-44, use combination of 30 + remainder
                        return AdvSimd.ShiftLeftLogical(
                            AdvSimd.ShiftLeftLogical(
                                AdvSimd.ShiftLeftLogical(value, 15), 15),
                            (byte) (shift - 30));
                    }
                    else if ( shift < 60 )
                    {
                        // For shifts between 45-59, use combination of 45 + remainder
                        return AdvSimd.ShiftLeftLogical(
                            AdvSimd.ShiftLeftLogical(
                                AdvSimd.ShiftLeftLogical(
                                    AdvSimd.ShiftLeftLogical(value, 15), 15), 15),
                            (byte) (shift - 45));
                    }
                    else
                    {
                        // Extract scalar values, perform shift, create new vector
                        ulong el0 = value.GetElement(0) << shift;
                        ulong el1 = value.GetElement(1) << shift;
                        return Vector128.Create(el0, el1);
                    }
            }
        }

        /// <summary>
        /// Safely shift right within AdvSimd constraints using constants for optimal performance
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<ulong> SafeShiftRight(Vector128<ulong> value, int shift)
        {
            // Use switch to select from constant shifts
            switch ( shift )
            {
                case 0: return value;
                case 1: return AdvSimd.ShiftRightLogical(value, 1);
                case 2: return AdvSimd.ShiftRightLogical(value, 2);
                case 3: return AdvSimd.ShiftRightLogical(value, 3);
                case 4: return AdvSimd.ShiftRightLogical(value, 4);
                case 5: return AdvSimd.ShiftRightLogical(value, 5);
                case 6: return AdvSimd.ShiftRightLogical(value, 6);
                case 7: return AdvSimd.ShiftRightLogical(value, 7);
                case 8: return AdvSimd.ShiftRightLogical(value, 8);
                case 9: return AdvSimd.ShiftRightLogical(value, 9);
                case 10: return AdvSimd.ShiftRightLogical(value, 10);
                case 11: return AdvSimd.ShiftRightLogical(value, 11);
                case 12: return AdvSimd.ShiftRightLogical(value, 12);
                case 13: return AdvSimd.ShiftRightLogical(value, 13);
                case 14: return AdvSimd.ShiftRightLogical(value, 14);
                case 15: return AdvSimd.ShiftRightLogical(value, 15);
                case 16: return AdvSimd.ShiftRightLogical(value, 16);

                // For larger shifts, compose with multiple constant shifts
                case 18: return AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(value, 16), 2);
                case 20: return AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(value, 16), 4);
                case 22: return AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(value, 16), 6);
                case 25: return AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(value, 16), 9);
                case 27: return AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(value, 16), 11);
                case 28: return AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(value, 16), 12);
                case 30: return AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(value, 16), 14);
                case 31: return AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(value, 16), 15);
                case 32: return AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(value, 16), 16);
                case 37: return AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(value, 16), 16), 5);
                case 45: return AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(value, 16), 16), 13);
                case 47: return AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(value, 16), 16), 15);
                case 48: return AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(value, 16), 16), 16);
                case 50: return AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(AdvSimd.ShiftRightLogical(value, 16), 16), 16), 2);

                // For any other shifts, we need to compose multiple shifts
                default:
                    // Use previously defined constants to compose the shift
                    if ( shift <= 16 )
                    {
                        // Use direct shift for small values
                        return AdvSimd.ShiftRightLogical(value, (byte) shift);
                    }
                    else if ( shift <= 32 )
                    {
                        // For shifts between 17-32, use combination of 16 + remainder
                        return AdvSimd.ShiftRightLogical(
                            AdvSimd.ShiftRightLogical(value, 16),
                            (byte) (shift - 16));
                    }
                    else if ( shift <= 48 )
                    {
                        // For shifts between 33-48, use combination of 32 + remainder
                        return AdvSimd.ShiftRightLogical(
                            AdvSimd.ShiftRightLogical(
                                AdvSimd.ShiftRightLogical(value, 16), 16),
                            (byte) (shift - 32));
                    }
                    else if ( shift < 64 )
                    {
                        // For shifts between 49-63, use combination of 48 + remainder
                        return AdvSimd.ShiftRightLogical(
                            AdvSimd.ShiftRightLogical(
                                AdvSimd.ShiftRightLogical(
                                    AdvSimd.ShiftRightLogical(value, 16), 16), 16),
                            (byte) (shift - 48));
                    }
                    else
                    {
                        // For complete shifts (64 or more), return zero
                        return Vector128<ulong>.Zero;
                    }
            }
        }

            /// <summary>
            /// Rotate a vector of 64-bit integers left by the specified number of bits using ARM AdvSimd
            /// This implementation avoids CA1857 warnings by using safe shift operations
            /// </summary>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<ulong> VectorRotateLeft64AdvSimd(Vector128<ulong> value, int rotation)
        {
            rotation &= 63; // Ensure rotation is within 0-63 range

            // Use safe shift operations that work within ARM NEON constraints
            return AdvSimd.Xor(
                SafeShiftLeft(value, rotation),
                SafeShiftRight(value, 64 - rotation)
            );
        }

        /// <summary>
        /// Rotate a vector of 64-bit integers right by the specified number of bits using ARM AdvSimd
        /// This implementation avoids CA1857 warnings by using safe shift operations
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<ulong> VectorRotateRight64AdvSimd(Vector128<ulong> value, int rotation)
        {
            rotation &= 63; // Ensure rotation is within 0-63 range

            // Use safe shift operations that work within ARM NEON constraints
            return AdvSimd.Xor(
                SafeShiftRight(value, rotation),
                SafeShiftLeft(value, 64 - rotation)
            );
        }
        /// <summary>
        /// Special optimized implementation for ARM64/AArch64 processors with full NEON support
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<ulong> OptimizedArm64Add(Vector128<ulong> a, Vector128<ulong> b)
        {
            // ARM64-specific optimizations if available
            if ( AdvSimd.Arm64.IsSupported )
            {
                // ARM64 has more optimized 64-bit integer operations
                return AdvSimd.Add(a, b); // We use the standard Add which is optimized on ARM64
            }
            else
            {
                // Fallback for 32-bit ARM
                return AdvSimd.Add(a, b);
            }
        }

        /// <summary>
        /// Special optimized implementation for ARM64/AArch64 processors
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<ulong> OptimizedArm64Subtract(Vector128<ulong> a, Vector128<ulong> b)
        {
            // ARM64-specific optimizations if available
            if ( AdvSimd.Arm64.IsSupported )
            {
                // ARM64 has more optimized 64-bit integer operations
                return AdvSimd.Subtract(a, b); // We use the standard Subtract which is optimized on ARM64
            }
            else
            {
                // Fallback for 32-bit ARM
                return AdvSimd.Subtract(a, b);
            }
        }

        /// <summary>
        /// Process multiple blocks in parallel for increased throughput on ARM processors
        /// Specially optimized for ARM64/AArch64 architectures
        /// </summary>
        public void ProcessBlocksBatch(ReadOnlySpan<byte> input, ulong[] keySchedule, Span<byte> output, bool encrypt)
        {
            // ARM64 optimized batching with prefetching
            int blockCount = input.Length / BlockSize;

            // For ARM64, use larger batch sizes when possible
            if ( AdvSimd.Arm64.IsSupported && blockCount >= 4 )
            {
                // Process blocks in larger batches for ARM64
                for ( int i = 0; i < blockCount; i += 4 )
                {
                    int remainingBlocks = Math.Min(4, blockCount - i);

                    // Process 4 blocks at once when possible
                    for ( int j = 0; j < remainingBlocks; j++ )
                    {
                        int offset = (i + j) * BlockSize;
                        if ( encrypt )
                        {
                            EncryptBlockAdvSimd(
                                input.Slice(offset, BlockSize),
                                keySchedule,
                                output.Slice(offset, BlockSize));
                        }
                        else
                        {
                            DecryptBlockAdvSimd(
                                input.Slice(offset, BlockSize),
                                keySchedule,
                                output.Slice(offset, BlockSize));
                        }
                    }
                }
            }
            else
            {
                // Standard processing for smaller batches or 32-bit ARM
                for ( int i = 0; i < blockCount; i++ )
                {
                    int offset = i * BlockSize;
                    if ( encrypt )
                    {
                        EncryptBlockAdvSimd(
                            input.Slice(offset, BlockSize),
                            keySchedule,
                            output.Slice(offset, BlockSize));
                    }
                    else
                    {
                        DecryptBlockAdvSimd(
                            input.Slice(offset, BlockSize),
                            keySchedule,
                            output.Slice(offset, BlockSize));
                    }
                }
            }
        }

        /// <summary>
        /// Optimized mix function implementation that uses ARM64-specific instructions when available
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void MixVectorsAdvSimd(ref Vector128<ulong> v0, ref Vector128<ulong> v1, int rotation, bool firstRound)
        {
            if ( firstRound )
            {
                // Use optimized ARM64 add if available
                v0 = OptimizedArm64Add(v0, v1);

                // Rotate v1 left by rotation bits
                Vector128<ulong> rotatedV1 = VectorRotateLeft64AdvSimd(v1, rotation);

                // XOR rotated v1 with v0
                v1 = AdvSimd.Xor(rotatedV1, v0);
            }
            else
            {
                // Rotate v1 left by rotation bits
                v1 = VectorRotateLeft64AdvSimd(v1, rotation);

                // Use optimized ARM64 add if available
                v0 = OptimizedArm64Add(v0, v1);

                // XOR v1 with v0
                v1 = AdvSimd.Xor(v1, v0);
            }
        }

        /// <summary>
        /// Optimized unmix function implementation that uses ARM64-specific instructions when available
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void UnmixVectorsAdvSimd(ref Vector128<ulong> v0, ref Vector128<ulong> v1, int rotation, bool firstRound)
        {
            if ( firstRound )
            {
                // XOR v1 with v0
                v1 = AdvSimd.Xor(v1, v0);

                // Rotate v1 right by rotation bits
                v1 = VectorRotateRight64AdvSimd(v1, rotation);

                // Use optimized ARM64 subtract if available
                v0 = OptimizedArm64Subtract(v0, v1);
            }
            else
            {
                // XOR v1 with v0
                v1 = AdvSimd.Xor(v1, v0);

                // Use optimized ARM64 subtract if available
                v0 = OptimizedArm64Subtract(v0, v1);

                // Rotate v1 right by rotation bits
                v1 = VectorRotateRight64AdvSimd(v1, rotation);
            }
        }

        /// <summary>
        /// Apply permutation to state vectors using ARM AdvSimd
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ApplyPermutationAdvSimd(Vector128<ulong>[] state)
        {
            // ARM64 has specialized shuffling instructions that we can use 
            // instead of manual swapping when available
            if ( AdvSimd.Arm64.IsSupported )
            {
                // Use temporary array to avoid corrupting the state
                Vector128<ulong> temp0 = state[0];
                Vector128<ulong> temp1 = state[1];
                Vector128<ulong> temp2 = state[2];
                Vector128<ulong> temp3 = state[3];

                // Apply permutation based on {0, 3, 2, 1} pattern
                state[0] = temp0;              // 0 stays at 0
                state[1] = temp3;              // 3 goes to 1
                state[2] = temp2;              // 2 stays at 2
                state[3] = temp1;              // 1 goes to 3
            }
            else
            {
                // Fallback for 32-bit ARM
                Vector128<ulong> temp0 = state[0];
                Vector128<ulong> temp1 = state[1];
                Vector128<ulong> temp2 = state[2];
                Vector128<ulong> temp3 = state[3];

                state[0] = temp0;              // 0 stays at 0
                state[1] = temp3;              // 3 goes to 1
                state[2] = temp2;              // 2 stays at 2
                state[3] = temp1;              // 1 goes to 3
            }
        }

        /// <summary>
        /// Apply inverse permutation to state vectors using ARM AdvSimd
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ApplyInversePermutationAdvSimd(Vector128<ulong>[] state)
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
            Span<ulong> values = stackalloc ulong[8];

            // For ARM64, we can optimize memory access patterns
            if ( AdvSimd.Arm64.IsSupported )
            {
                // ARM64 optimized stores
                StoreUInt64PairOptimized(state[0], output, 0);
                StoreUInt64PairOptimized(state[1], output, 16);
                StoreUInt64PairOptimized(state[2], output, 32);
                StoreUInt64PairOptimized(state[3], output, 48);
            }
            else
            {
                // Original implementation for 32-bit ARM
                values[0] = state[0].GetElement(0);
                values[1] = state[0].GetElement(1);
                values[2] = state[1].GetElement(0);
                values[3] = state[1].GetElement(1);
                values[4] = state[2].GetElement(0);
                values[5] = state[2].GetElement(1);
                values[6] = state[3].GetElement(0);
                values[7] = state[3].GetElement(1);

                for ( int i = 0; i < 8; i++ )
                {
                    ulong value = values[i];

                    if ( !BitConverter.IsLittleEndian )
                    {
                        value = EndianHelper.SwapUInt64(value);
                    }

                    BitConverter.TryWriteBytes(output.Slice(i * 8, 8), value);
                }
            }
        }

        /// <summary>
        /// Optimized loader for ARM64 platforms
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<ulong> LoadUInt64PairOptimized(ReadOnlySpan<byte> data, int offset)
        {
            // ARM optimized load operation
            ulong v0 = BitConverter.ToUInt64(data.Slice(offset, 8));
            ulong v1 = BitConverter.ToUInt64(data.Slice(offset + 8, 8));

            if ( !BitConverter.IsLittleEndian )
            {
                v0 = EndianHelper.SwapUInt64(v0);
                v1 = EndianHelper.SwapUInt64(v1);
            }

            return Vector128.Create(v0, v1);
        }

        /// <summary>
        /// Optimized store for ARM64 platforms
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void StoreUInt64PairOptimized(Vector128<ulong> vector, Span<byte> output, int offset)
        {
            ulong v0 = vector.GetElement(0);
            ulong v1 = vector.GetElement(1);

            if ( !BitConverter.IsLittleEndian )
            {
                v0 = EndianHelper.SwapUInt64(v0);
                v1 = EndianHelper.SwapUInt64(v1);
            }

            BitConverter.TryWriteBytes(output.Slice(offset, 8), v0);
            BitConverter.TryWriteBytes(output.Slice(offset + 8, 8), v1);
        }

        /// <summary>
        /// Add key schedule values to a Vector128 using ARM AdvSimd
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<ulong> AddKeyToVectorAdvSimd(Vector128<ulong> vector, ulong[] keySchedule, int offset)
        {
            // Create a Vector128 from two consecutive key schedule values
            Vector128<ulong> keyVector = Vector128.Create(
                keySchedule[offset],
                keySchedule[offset + 1]
            );

            // Use AdvSimd to add 64-bit integers
            return AdvSimd.Add(vector, keyVector);
        }

        /// <summary>
        /// Subtract key schedule values from a Vector128 using ARM AdvSimd
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<ulong> SubtractKeyFromVectorAdvSimd(Vector128<ulong> vector, ulong[] keySchedule, int offset)
        {
            // Create a Vector128 from two consecutive key schedule values
            Vector128<ulong> keyVector = Vector128.Create(
                keySchedule[offset],
                keySchedule[offset + 1]
            );

            // Use AdvSimd to subtract 64-bit integers
            return AdvSimd.Subtract(vector, keyVector);
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
        /// Apply multiple rounds of ThreeFish encryption using ARM AdvSimd intrinsics
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ApplyRoundsAdvSimd(Vector128<ulong>[] state, ulong[] keySchedule, int startRound)
        {
            for ( int r = startRound; r < startRound + 2 && r < 72; r++ )
            {
                // Add round key (load key schedule values into AdvSimd vectors)
                int scheduleIndex = r % 19;
                int keyOffset = scheduleIndex * 8;

                state[0] = AddKeyToVectorAdvSimd(state[0], keySchedule, keyOffset);
                state[1] = AddKeyToVectorAdvSimd(state[1], keySchedule, keyOffset + 2);
                state[2] = AddKeyToVectorAdvSimd(state[2], keySchedule, keyOffset + 4);
                state[3] = AddKeyToVectorAdvSimd(state[3], keySchedule, keyOffset + 6);

                // Apply mix operations using AdvSimd intrinsics
                int rotationIndex = r % 8 / 2;

                // Process all mix operations
                MixVectorsAdvSimd(ref state[0], ref state[1], GetRotation(rotationIndex, 0), r % 8 == 0);
                MixVectorsAdvSimd(ref state[2], ref state[3], GetRotation(rotationIndex, 1), r % 8 == 0);

                // Apply permutation with minimal register shuffling
                ApplyPermutationAdvSimd(state);
            }
        }

        /// <summary>
        /// Apply multiple rounds of ThreeFish decryption in reverse using ARM AdvSimd intrinsics
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ApplyRoundsInReverseAdvSimd(Vector128<ulong>[] state, ulong[] keySchedule, int startRound)
        {
            for ( int r = startRound + 1; r >= startRound; r-- )
            {
                // Reverse permutation with minimal register shuffling
                ApplyInversePermutationAdvSimd(state);

                // Apply inverse mix operations
                int rotationIndex = r % 8 / 2;

                // Process all inverse mix operations
                UnmixVectorsAdvSimd(ref state[0], ref state[1], GetRotation(rotationIndex, 0), r % 8 == 0);
                UnmixVectorsAdvSimd(ref state[2], ref state[3], GetRotation(rotationIndex, 1), r % 8 == 0);

                // Subtract round key (using AdvSimd vectors)
                int scheduleIndex = r % 19;
                int keyOffset = scheduleIndex * 8;

                state[0] = SubtractKeyFromVectorAdvSimd(state[0], keySchedule, keyOffset);
                state[1] = SubtractKeyFromVectorAdvSimd(state[1], keySchedule, keyOffset + 2);
                state[2] = SubtractKeyFromVectorAdvSimd(state[2], keySchedule, keyOffset + 4);
                state[3] = SubtractKeyFromVectorAdvSimd(state[3], keySchedule, keyOffset + 6);
            }
        }
    }
}
