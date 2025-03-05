using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using Scuttle.Helpers;

namespace Scuttle.Encrypt.ChaChaCore
{
    internal static class Poly1305
    {
        public static byte[] ComputeTag(byte[] key, ReadOnlySpan<byte> message)
        {
            if ( key.Length != 32 )
                throw new ArgumentException("Poly1305 key must be 32 bytes.");

            // Initialize r and s from key with clamping applied
            Span<byte> r = stackalloc byte[16];
            Span<byte> s = stackalloc byte[16];
            key.AsSpan(0, 16).CopyTo(r);
            key.AsSpan(16, 16).CopyTo(s);

            // Clamp r (clear specific bits as per the Poly1305 spec)
            r[3] &= 15;
            r[7] &= 15;
            r[11] &= 15;
            r[15] &= 15;
            r[4] &= 252;
            r[8] &= 252;
            r[12] &= 252;

            // Convert to uint values with correct endianness
            Span<uint> rNum = stackalloc uint[4];
            Span<uint> sNum = stackalloc uint[4];

            // Optimize with SIMD if available
            if ( Sse2.IsSupported )
            {
                // Load bytes into SIMD registers and convert to uint32 values
                var rVector = Vector128.Create(
                    BitConverter.ToUInt32(r.Slice(0, 4)),
                    BitConverter.ToUInt32(r.Slice(4, 4)),
                    BitConverter.ToUInt32(r.Slice(8, 4)),
                    BitConverter.ToUInt32(r.Slice(12, 4))
                );

                var sVector = Vector128.Create(
                    BitConverter.ToUInt32(s.Slice(0, 4)),
                    BitConverter.ToUInt32(s.Slice(4, 4)),
                    BitConverter.ToUInt32(s.Slice(8, 4)),
                    BitConverter.ToUInt32(s.Slice(12, 4))
                );

                // Store back to rNum and sNum spans
                Unsafe.As<uint, Vector128<uint>>(ref rNum[0]) = rVector;
                Unsafe.As<uint, Vector128<uint>>(ref sNum[0]) = sVector;
            }
            else
            {
                for ( int i = 0; i < 4; i++ )
                {
                    rNum[i] = (uint) (r[i * 4] | (r[i * 4 + 1] << 8) | (r[i * 4 + 2] << 16) | (r[i * 4 + 3] << 24));
                    sNum[i] = (uint) (s[i * 4] | (s[i * 4 + 1] << 8) | (s[i * 4 + 2] << 16) | (s[i * 4 + 3] << 24));
                }
            }

            // Initialize accumulator
            ulong h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

            // Process message blocks
            int blockSize = 16;
            int blocksCount = (message.Length + blockSize - 1) / blockSize;

            for ( int i = 0; i < blocksCount; i++ )
            {
                int blockLen = Math.Min(blockSize, message.Length - i * blockSize);
                uint[] block = ArrayPool<uint>.Shared.Rent(4);

                try
                {
                    if ( blockLen == 16 )
                    {
                        ReadOnlySpan<byte> blockSpan = message.Slice(i * 16, 16);
                        block[0] = BitConverter.ToUInt32(blockSpan.Slice(0, 4));
                        block[1] = BitConverter.ToUInt32(blockSpan.Slice(4, 4));
                        block[2] = BitConverter.ToUInt32(blockSpan.Slice(8, 4));
                        block[3] = BitConverter.ToUInt32(blockSpan.Slice(12, 4));
                    }
                    else
                    {
                        Span<byte> padding = stackalloc byte[16];
                        message.Slice(i * 16, blockLen).CopyTo(padding);
                        padding[blockLen] = 1; // Add 1 byte after the message as per Poly1305

                        block[0] = BitConverter.ToUInt32(padding.Slice(0, 4));
                        block[1] = BitConverter.ToUInt32(padding.Slice(4, 4));
                        block[2] = BitConverter.ToUInt32(padding.Slice(8, 4));
                        block[3] = BitConverter.ToUInt32(padding.Slice(12, 4));
                    }

                    // Add block to accumulator
                    ulong t0 = h0 + block[0];
                    ulong t1 = h1 + block[1];
                    ulong t2 = h2 + block[2];
                    ulong t3 = h3 + block[3];

                    h0 = (uint) t0; h1 = (uint) t1; h2 = (uint) t2; h3 = (uint) t3;
                    h4 += (uint) (t0 >> 32 | t1 >> 32 | t2 >> 32 | t3 >> 32);

                    // Multiply by r using optimized multiplication
                    ulong d0 = h0 * (ulong) rNum[0] +
                               h1 * (ulong) rNum[3] +
                               h2 * (ulong) rNum[2] +
                               h3 * (ulong) rNum[1];

                    ulong d1 = h0 * (ulong) rNum[1] +
                               h1 * (ulong) rNum[0] +
                               h2 * (ulong) rNum[3] +
                               h3 * (ulong) rNum[2];

                    ulong d2 = h0 * (ulong) rNum[2] +
                               h1 * (ulong) rNum[1] +
                               h2 * (ulong) rNum[0] +
                               h3 * (ulong) rNum[3];

                    ulong d3 = h0 * (ulong) rNum[3] +
                               h1 * (ulong) rNum[2] +
                               h2 * (ulong) rNum[1] +
                               h3 * (ulong) rNum[0];

                    // Partial reduction modulo 2^130 - 5
                    ulong c = d0 >> 32;
                    h0 = (uint) d0;
                    d1 += c;

                    c = d1 >> 32;
                    h1 = (uint) d1;
                    d2 += c;

                    c = d2 >> 32;
                    h2 = (uint) d2;
                    d3 += c;

                    c = d3 >> 32;
                    h3 = (uint) d3;
                    h4 = h4 * (uint) rNum[0] + (uint) c;

                    c = h4 >> 2;
                    h4 &= 3;
                    h0 += c * 5;
                    h1 += h0 >> 32;
                    h0 &= 0xffffffff;
                }
                finally
                {
                    // Return rented array to pool
                    ArrayPool<uint>.Shared.Return(block);
                }
            }

            // Final reduction and addition of s
            ulong f0 = h0 + sNum[0];
            ulong f1 = h1 + sNum[1] + (f0 >> 32);
            ulong f2 = h2 + sNum[2] + (f1 >> 32);
            ulong f3 = h3 + sNum[3] + (f2 >> 32);

            h0 = (uint) f0; h1 = (uint) f1;
            h2 = (uint) f2; h3 = (uint) f3;

            // Format the result as a 16-byte tag
            byte[] tag = new byte[16];

            // Use direct writes for better performance - explicit cast down to uInt since these values are meant to fit with 32 bits after modular ops
            EndianHelper.WriteUInt32ToTag((uint) h0, tag, 0);
            EndianHelper.WriteUInt32ToTag((uint) h1, tag, 4);
            EndianHelper.WriteUInt32ToTag((uint) h2, tag, 8);
            EndianHelper.WriteUInt32ToTag((uint) h3, tag, 12);

            return tag;
        }
    }
}
