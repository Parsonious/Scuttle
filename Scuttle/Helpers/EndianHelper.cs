using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace Scuttle.Helpers
{
    internal static class EndianHelper
    {
        private static readonly bool _isLittleEndian = BitConverter.IsLittleEndian;

        //INT32
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void MassageUInt32Array(Span<uint> data)
        {
            if ( _isLittleEndian ) return; // No conversion needed for little-endian systems

            for ( int i = 0; i < data.Length; i++ )
            {
                data[i] = SwapUInt32(data[i]);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint[] MassageToUInt32Array(ReadOnlySpan<byte> data, int offset, int count)
        {
            int uintCount = (count + 3) / 4;
            uint[] result = new uint[uintCount];

            // Optimize for the common case where data is properly aligned
            if ( offset % 4 == 0 && count % 4 == 0 && data.Length >= offset + count )
            {
                for ( int i = 0; i < uintCount; i++ )
                {
                    int byteOffset = offset + (i * 4);
                    result[i] = BinaryPrimitives.ReadUInt32LittleEndian(data[byteOffset..]);
                }
            }
            else
            {
                Span<byte> temp = stackalloc byte[4];

                // Handle unaligned or partial data
                for ( int i = 0; i < uintCount; i++ )
                {
                    int byteOffset = offset + (i * 4);
                    int remainingBytes = Math.Min(4, count - (i * 4));

                    if ( remainingBytes < 4 )
                    {
                        data.Slice(byteOffset, remainingBytes).CopyTo(temp);
                        result[i] = BinaryPrimitives.ReadUInt32LittleEndian(temp);
                    }
                    else
                    {
                        result[i] = BinaryPrimitives.ReadUInt32LittleEndian(data[byteOffset..]);
                    }
                }
            }

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteUInt32ToBytes(uint value, Span<byte> output)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(output, value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteUInt32ToBytes(uint value, byte[] output, int offset)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(offset, 4), value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteUInt32ToTag(uint value, byte[] tag, int offset)
        {
            // Same implementation as WriteUInt32ToBytes for consistency
            WriteUInt32ToBytes(value, tag, offset);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint SwapUInt32(uint value)
        {
            return BinaryPrimitives.ReverseEndianness(value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong[] MassageToUInt64Array(ReadOnlySpan<byte> data, int offset, int count)
        {
            int ulongCount = (count + 7) / 8;
            ulong[] result = new ulong[ulongCount];

            // Optimize for the common case where data is properly aligned
            if ( offset % 8 == 0 && count % 8 == 0 && data.Length >= offset + count )
            {
                for ( int i = 0; i < ulongCount; i++ )
                {
                    int byteOffset = offset + (i * 8);
                    result[i] = BinaryPrimitives.ReadUInt64LittleEndian(data[byteOffset..]);
                }
            }
            else
            {
                Span<byte> temp = stackalloc byte[8];
                // Handle unaligned or partial data
                for ( int i = 0; i < ulongCount; i++ )
                {
                    int byteOffset = offset + (i * 8);
                    int remainingBytes = Math.Min(8, count - (i * 8));

                    if ( remainingBytes < 8 )
                    {
                        data.Slice(byteOffset, remainingBytes).CopyTo(temp);
                        result[i] = BinaryPrimitives.ReadUInt64LittleEndian(temp);
                    }
                    else
                    {
                        result[i] = BinaryPrimitives.ReadUInt64LittleEndian(data[byteOffset..]);
                    }
                }
            }

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteUInt64ToBytes(ulong value, Span<byte> destination)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(destination, value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong SwapUInt64(ulong value)
        {
            return BinaryPrimitives.ReverseEndianness(value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void MassageUInt64Array(Span<ulong> data)
        {
            if ( _isLittleEndian ) return; // No conversion needed for little-endian systems

            for ( int i = 0; i < data.Length; i++ )
            {
                data[i] = SwapUInt64(data[i]);
            }
        }
    }
}
