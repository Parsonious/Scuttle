using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Scuttle.Helpers;

namespace Scuttle.Encrypt.Strategies.ThreeFish
{
    /// <summary>
    /// Base abstract strategy for ThreeFish implementations that provides common functionality
    /// </summary>
    internal abstract class BaseThreeFishStrategy : IThreeFishStrategy
    {
        // Constants
        protected const int KeySize = 64;    // 512 bits
        protected const int TweakSize = 16;  // 128 bits
        protected const int BlockSize = 64;  // 512 bits
        protected const ulong Const240 = 0x1BD11BDAA9FC1A22;

        protected static readonly int[] Rotation_0_0 = [46, 36, 19, 37];
        protected static readonly int[] Rotation_1_0 = [33, 27, 14, 42];
        protected static readonly int[] Rotation_2_0 = [17, 49, 36, 39];
        protected static readonly int[] Rotation_3_0 = [44, 39, 56, 34];
        protected static readonly int[] Permutation = [0, 3, 2, 1];

        /// <summary>
        /// The priority of this strategy (higher numbers are preferred)
        /// </summary>
        public abstract int Priority { get; }

        /// <summary>
        /// A description of this strategy for diagnostic purposes
        /// </summary>
        public abstract string Description { get; }

        /// <summary>
        /// Encrypts data using ThreeFish
        /// </summary>
        public abstract byte[] Encrypt(byte[] data, byte[] key);

        /// <summary>
        /// Decrypts data encrypted with ThreeFish
        /// </summary>
        public abstract byte[] Decrypt(byte[] encryptedData, byte[] key);

        /// <summary>
        /// Validates input parameters for encryption methods
        /// </summary>
        protected static void ValidateInputs(byte[] data, byte[] key)
        {
            if ( data == null || data.Length == 0 )
                throw new ArgumentException("Data cannot be null or empty.", nameof(data));
            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));
        }

        /// <summary>
        /// Generates key schedule for ThreeFish algorithm
        /// </summary>
        protected ulong[] GenerateKeySchedule(byte[] key, byte[] tweak)
        {
            Span<ulong> k = stackalloc ulong[9];  // 8 key words + key parity word
            Span<ulong> t = stackalloc ulong[3];  // 2 tweak words + tweak parity word

            // Convert key and tweak with proper endianness
            var keyWords = EndianHelper.MassageToUInt64Array(key, 0, key.Length);
            keyWords.AsSpan().CopyTo(k[..8]);

            if ( tweak != null )
            {
                var tweakWords = EndianHelper.MassageToUInt64Array(tweak, 0, tweak.Length);
                t[0] = tweakWords[0];
                t[1] = tweakWords[1];
            }

            // Calculate parity words
            k[8] = Const240;
            for ( int i = 0; i < 8; i++ )
            {
                k[8] ^= k[i];
            }
            t[2] = t[0] ^ t[1];

            // Generate schedule with proper endianness
            ulong[] schedule = new ulong[19 * 8];
            for ( int s = 0; s < 19; s++ )
            {
                for ( int i = 0; i < 8; i++ )
                {
                    schedule[s * 8 + i] = k[(s + i) % 9];
                }

                schedule[s * 8] += t[s % 3];
                schedule[s * 8 + 1] += t[(s + 1) % 3];
                schedule[s * 8 + 2] += (ulong) s;
            }

            return schedule;
        }

        /// <summary>
        /// Implements mix function for ThreeFish
        /// </summary>
        protected static void MixFunction(ref ulong x0, ref ulong x1, int rotation, bool firstRound)
        {
            if ( firstRound )
            {
                x0 += x1;
                x1 = CryptoEndianness.RotateLeft64(x1, rotation) ^ x0;
            }
            else
            {
                x1 = CryptoEndianness.RotateLeft64(x1, rotation);
                x0 += x1;
                x1 ^= x0;
            }
        }

        /// <summary>
        /// Implements unmix function for ThreeFish (inverse of mix function)
        /// </summary>
        protected static void UnmixFunction(ref ulong x0, ref ulong x1, int rotation, bool firstRound)
        {
            if ( firstRound )
            {
                x1 ^= x0;
                x1 = CryptoEndianness.RotateLeft64(x1, -rotation); // Negative for right rotation
                x0 -= x1;
            }
            else
            {
                x1 ^= x0;
                x0 -= x1;
                x1 = CryptoEndianness.RotateLeft64(x1, -rotation); // Negative for right rotation
            }
        }
    }
}
