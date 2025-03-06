using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Scuttle.Helpers;

namespace Scuttle.Encrypt.Strategies.ThreeFish
{
    /// <summary>
    /// Scalar (non-SIMD) implementation of ThreeFish for all platforms
    /// </summary>
    internal class ThreeFishScalarStrategy : BaseThreeFishStrategy
    {
        public override int Priority => 100; // Lowest priority
        public override string Description => "Scalar ThreeFish Implementation";

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
                EncryptBlockInPlace(block, keySchedule, encryptedBlock);
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
                DecryptBlockInPlace(block, keySchedule, decryptedBlock);
                decryptedBlock.CopyTo(decrypted.AsSpan(i, BlockSize));
            }

            // Remove padding and trim to original length
            byte[] result = new byte[originalLength];
            Buffer.BlockCopy(decrypted, 0, result, 0, originalLength);

            return result;
        }

        private void EncryptBlockInPlace(ReadOnlySpan<byte> input, ulong[] keySchedule, Span<byte> output)
        {
            // Stack-allocate state arrays for better performance
            Span<ulong> state = stackalloc ulong[8];
            Span<ulong> tempState = stackalloc ulong[8];

            // Initialize state
            CryptoEndianness.InitializeThreeFishState(state, input, null);

            // Process rounds
            for ( int round = 0; round < 72; round++ )
            {
                // Add round key
                for ( int i = 0; i < 8; i++ )
                {
                    state[i] += keySchedule[(round % 19) * 8 + i];
                }

                // Apply mix operations
                for ( int i = 0; i < 4; i++ )
                {
                    MixFunction(ref state[i * 2], ref state[i * 2 + 1],
                        GetRotation(round % 8 / 2, i), round % 8 == 0);
                }

                // Apply permutation
                tempState[0] = state[Permutation[0]];
                tempState[1] = state[Permutation[1]];
                tempState[2] = state[Permutation[2]];
                tempState[3] = state[Permutation[3]];
                tempState[4] = state[Permutation[0] + 4];
                tempState[5] = state[Permutation[1] + 4];
                tempState[6] = state[Permutation[2] + 4];
                tempState[7] = state[Permutation[3] + 4];

                // Swap buffers
                var swap = state;
                state = tempState;
                tempState = swap;
            }

            // Process final block
            CryptoEndianness.ProcessBlock64(output, state);
        }

        private void DecryptBlockInPlace(ReadOnlySpan<byte> input, ulong[] keySchedule, Span<byte> output)
        {
            // Pre-allocate all state arrays
            Span<ulong> state = stackalloc ulong[8];
            Span<ulong> tempState = stackalloc ulong[8];

            // Initialize state with proper endianness
            CryptoEndianness.InitializeThreeFishState(state, input, null);

            // Reverse the 72 rounds
            for ( int round = 71; round >= 0; round-- )
            {
                // Reverse permutation using pre-allocated arrays
                for ( int i = 0; i < 8; i++ )
                {
                    int permIndex = Permutation[i % 4] + (i / 4) * 4;
                    tempState[i] = state[permIndex];
                }
                tempState.CopyTo(state);

                // Reverse mix operations
                for ( int i = 3; i >= 0; i-- )
                {
                    UnmixFunction(ref state[i * 2], ref state[i * 2 + 1],
                        GetRotation(round % 8 / 2, i), round % 8 == 0);
                }

                // Subtract round key
                for ( int i = 0; i < 8; i++ )
                {
                    state[i] -= keySchedule[(round % 19) * 8 + i];
                }
            }

            // Process final block with proper endianness
            CryptoEndianness.ProcessBlock64(output, state);
        }

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
        /// Scalar implementation is always supported
        /// </summary>
        public static bool IsSupported => true;
    }
}
