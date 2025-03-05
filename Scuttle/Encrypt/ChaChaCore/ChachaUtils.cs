using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics.Arm;
using System.Numerics;
using System.Runtime.InteropServices;

namespace Scuttle.Encrypt.ChaChaCore
{
    internal static class ChaChaUtils
    {
        // Core quarter round operation - identical for both implementations
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b; d ^= a; d = BitOperations.RotateLeft(d, 16);
            c += d; b ^= c; b = BitOperations.RotateLeft(b, 12);
            a += b; d ^= a; d = BitOperations.RotateLeft(d, 8);
            c += d; b ^= c; b = BitOperations.RotateLeft(b, 7);
        }
        // Perform ChaCha20 round using SSE2 instructions
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ChaChaRoundSse2(
            ref Vector128<uint> a, ref Vector128<uint> b,
            ref Vector128<uint> c, ref Vector128<uint> d)
        {
            // Column round
            a = Sse2.Add(a, b);
            d = Sse2.Xor(d, a);
            d = Sse2.Or(Sse2.ShiftLeftLogical(d, 16), Sse2.ShiftRightLogical(d, 32 - 16));

            c = Sse2.Add(c, d);
            b = Sse2.Xor(b, c);
            b = Sse2.Or(Sse2.ShiftLeftLogical(b, 12), Sse2.ShiftRightLogical(b, 32 - 12));

            a = Sse2.Add(a, b);
            d = Sse2.Xor(d, a);
            d = Sse2.Or(Sse2.ShiftLeftLogical(d, 8), Sse2.ShiftRightLogical(d, 32 - 8));

            c = Sse2.Add(c, d);
            b = Sse2.Xor(b, c);
            b = Sse2.Or(Sse2.ShiftLeftLogical(b, 7), Sse2.ShiftRightLogical(b, 32 - 7));

            // Diagonal round - shuffle vectors to get diagonal elements
            b = Sse2.Shuffle(b, 0x39); // Rotate left 1
            c = Sse2.Shuffle(c, 0x4E); // Rotate left 2
            d = Sse2.Shuffle(d, 0x93); // Rotate left 3

            a = Sse2.Add(a, b);
            d = Sse2.Xor(d, a);
            d = Sse2.Or(Sse2.ShiftLeftLogical(d, 16), Sse2.ShiftRightLogical(d, 32 - 16));

            c = Sse2.Add(c, d);
            b = Sse2.Xor(b, c);
            b = Sse2.Or(Sse2.ShiftLeftLogical(b, 12), Sse2.ShiftRightLogical(b, 32 - 12));

            a = Sse2.Add(a, b);
            d = Sse2.Xor(d, a);
            d = Sse2.Or(Sse2.ShiftLeftLogical(d, 8), Sse2.ShiftRightLogical(d, 32 - 8));

            c = Sse2.Add(c, d);
            b = Sse2.Xor(b, c);
            b = Sse2.Or(Sse2.ShiftLeftLogical(b, 7), Sse2.ShiftRightLogical(b, 32 - 7));

            // Restore original positions
            b = Sse2.Shuffle(b, 0x93); // Rotate right 1
            c = Sse2.Shuffle(c, 0x4E); // Rotate right 2
            d = Sse2.Shuffle(d, 0x39); // Rotate right 3
        }
        // Perform ChaCha20 round using ARM AdvSimd instructions
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ChaChaRoundAdvSimd(
            ref Vector128<uint> a, ref Vector128<uint> b,
            ref Vector128<uint> c, ref Vector128<uint> d)
        {
            // Column round
            a = AdvSimd.Add(a.AsUInt32(), b.AsUInt32()).AsUInt32();
            d = AdvSimd.Xor(d.AsUInt32(), a.AsUInt32()).AsUInt32();

            // Rotate left by 16
            d = AdvSimd.BitwiseSelect(
                AdvSimd.ShiftLeftLogical(d.AsUInt32(), 16),
                AdvSimd.ShiftRightLogical(d.AsUInt32(), 16),
                Vector128.Create(0xFFFF0000u, 0xFFFF0000u, 0xFFFF0000u, 0xFFFF0000u)).AsUInt32();

            c = AdvSimd.Add(c.AsUInt32(), d.AsUInt32()).AsUInt32();
            b = AdvSimd.Xor(b.AsUInt32(), c.AsUInt32()).AsUInt32();

            // Rotate left by 12
            b = AdvSimd.BitwiseSelect(
                AdvSimd.ShiftLeftLogical(b.AsUInt32(), 12),
                AdvSimd.ShiftRightLogical(b.AsUInt32(), 20),
                Vector128.Create(0xFFF00000u, 0xFFF00000u, 0xFFF00000u, 0xFFF00000u)).AsUInt32();

            a = AdvSimd.Add(a.AsUInt32(), b.AsUInt32()).AsUInt32();
            d = AdvSimd.Xor(d.AsUInt32(), a.AsUInt32()).AsUInt32();

            // Rotate left by 8
            d = AdvSimd.BitwiseSelect(
                AdvSimd.ShiftLeftLogical(d.AsUInt32(), 8),
                AdvSimd.ShiftRightLogical(d.AsUInt32(), 24),
                Vector128.Create(0xFF000000u, 0xFF000000u, 0xFF000000u, 0xFF000000u)).AsUInt32();

            c = AdvSimd.Add(c.AsUInt32(), d.AsUInt32()).AsUInt32();
            b = AdvSimd.Xor(b.AsUInt32(), c.AsUInt32()).AsUInt32();

            // Rotate left by 7
            b = AdvSimd.BitwiseSelect(
                AdvSimd.ShiftLeftLogical(b.AsUInt32(), 7),
                AdvSimd.ShiftRightLogical(b.AsUInt32(), 25),
                Vector128.Create(0xFE000000u, 0xFE000000u, 0xFE000000u, 0xFE000000u)).AsUInt32();

            // Diagonal round - ARM NEON equivalent of shuffle
            // Rotate b left 1
            Vector128<uint> temp = b;
            b = Vector128.Create(temp.GetElement(1), temp.GetElement(2), temp.GetElement(3), temp.GetElement(0));

            // Rotate c left 2
            temp = c;
            c = Vector128.Create(temp.GetElement(2), temp.GetElement(3), temp.GetElement(0), temp.GetElement(1));

            // Rotate d left 3
            temp = d;
            d = Vector128.Create(temp.GetElement(3), temp.GetElement(0), temp.GetElement(1), temp.GetElement(2));

            // Repeat the same operations for diagonal round
            a = AdvSimd.Add(a.AsUInt32(), b.AsUInt32()).AsUInt32();
            d = AdvSimd.Xor(d.AsUInt32(), a.AsUInt32()).AsUInt32();

            // Rotate left by 16
            d = AdvSimd.BitwiseSelect(
                AdvSimd.ShiftLeftLogical(d.AsUInt32(), 16),
                AdvSimd.ShiftRightLogical(d.AsUInt32(), 16),
                Vector128.Create(0xFFFF0000u, 0xFFFF0000u, 0xFFFF0000u, 0xFFFF0000u)).AsUInt32();

            c = AdvSimd.Add(c.AsUInt32(), d.AsUInt32()).AsUInt32();
            b = AdvSimd.Xor(b.AsUInt32(), c.AsUInt32()).AsUInt32();

            // Rotate left by 12
            b = AdvSimd.BitwiseSelect(
                AdvSimd.ShiftLeftLogical(b.AsUInt32(), 12),
                AdvSimd.ShiftRightLogical(b.AsUInt32(), 20),
                Vector128.Create(0xFFF00000u, 0xFFF00000u, 0xFFF00000u, 0xFFF00000u)).AsUInt32();

            a = AdvSimd.Add(a.AsUInt32(), b.AsUInt32()).AsUInt32();
            d = AdvSimd.Xor(d.AsUInt32(), a.AsUInt32()).AsUInt32();

            // Rotate left by 8
            d = AdvSimd.BitwiseSelect(
                AdvSimd.ShiftLeftLogical(d.AsUInt32(), 8),
                AdvSimd.ShiftRightLogical(d.AsUInt32(), 24),
                Vector128.Create(0xFF000000u, 0xFF000000u, 0xFF000000u, 0xFF000000u)).AsUInt32();

            c = AdvSimd.Add(c.AsUInt32(), d.AsUInt32()).AsUInt32();
            b = AdvSimd.Xor(b.AsUInt32(), c.AsUInt32()).AsUInt32();

            // Rotate left by 7
            b = AdvSimd.BitwiseSelect(
                AdvSimd.ShiftLeftLogical(b.AsUInt32(), 7),
                AdvSimd.ShiftRightLogical(b.AsUInt32(), 25),
                Vector128.Create(0xFE000000u, 0xFE000000u, 0xFE000000u, 0xFE000000u)).AsUInt32();

            // Restore original positions
            // Rotate b right 1
            temp = b;
            b = Vector128.Create(temp.GetElement(3), temp.GetElement(0), temp.GetElement(1), temp.GetElement(2));

            // Rotate c right 2
            temp = c;
            c = Vector128.Create(temp.GetElement(2), temp.GetElement(3), temp.GetElement(0), temp.GetElement(1));

            // Rotate d right 3
            temp = d;
            d = Vector128.Create(temp.GetElement(1), temp.GetElement(2), temp.GetElement(3), temp.GetElement(0));
        }
        // Constant-time comparison to prevent timing attacks
        public static bool ConstantTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if ( a.Length != b.Length )
                return false;

            int result = 0;

            // Use SIMD for faster constant-time comparison when available
            if ( Sse2.IsSupported && a.Length >= Vector128<byte>.Count )
            {
                int vectorizedLength = a.Length - (a.Length % Vector128<byte>.Count);
                Vector128<byte> accumulator = Vector128<byte>.Zero;

                for ( int i = 0; i < vectorizedLength; i += Vector128<byte>.Count )
                {
                    var aVector = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(a.Slice(i)));
                    var bVector = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(b.Slice(i)));
                    var xorResult = Sse2.Xor(aVector, bVector);
                    accumulator = Sse2.Or(accumulator, xorResult);
                }

                // Convert vector comparison result to scalar
                for ( int i = 0; i < Vector128<byte>.Count; i++ )
                {
                    result |= accumulator.GetElement(i);
                }

                // Handle remaining bytes
                for ( int i = vectorizedLength; i < a.Length; i++ )
                {
                    result |= a[i] ^ b[i];
                }
            }
            else if ( AdvSimd.IsSupported && a.Length >= Vector128<byte>.Count )
            {
                // ARM NEON variant
                int vectorizedLength = a.Length - (a.Length % Vector128<byte>.Count);
                Vector128<byte> accumulator = Vector128<byte>.Zero;

                for ( int i = 0; i < vectorizedLength; i += Vector128<byte>.Count )
                {
                    var aVector = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(a.Slice(i)));
                    var bVector = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(b.Slice(i)));
                    var xorResult = AdvSimd.Xor(aVector, bVector);
                    accumulator = AdvSimd.Or(accumulator, xorResult);
                }

                // Convert vector comparison result to scalar
                for ( int i = 0; i < Vector128<byte>.Count; i++ )
                {
                    result |= accumulator.GetElement(i);
                }

                // Handle remaining bytes
                for ( int i = vectorizedLength; i < a.Length; i++ )
                {
                    result |= a[i] ^ b[i];
                }
            }
            else
            {
                // Scalar fallback for platforms without SIMD
                for ( int i = 0; i < a.Length; i++ )
                {
                    result |= a[i] ^ b[i];
                }
            }

            return result == 0;
        }
    }
}