using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace Scuttle.Helpers
{
    internal static class EndianHelper
    {
        private static readonly bool IsLittleEndian = BitConverter.IsLittleEndian;

        //INT32
        public static void MassageUInt32Array(Span<uint> data)
        {
            if ( IsLittleEndian ) return; // No conversion needed for little-endian systems

            for ( int i = 0; i < data.Length; i++ )
            {
                data[i] = ReverseUInt32(data[i]);
            }
        }
        public static uint[] MassageToUInt32Array(ReadOnlySpan<byte> data, int offset, int count)
        {
            int uintCount = (count + 3) / 4;
            uint[] result = new uint[uintCount];

            for ( int i = 0; i < uintCount; i++ )
            {
                int byteOffset = offset + (i * 4);
                int remainingBytes = Math.Min(4, count - (i * 4));

                if ( remainingBytes < 4 )
                {
                    Span<byte> temp = stackalloc byte[4];
                    data.Slice(byteOffset, remainingBytes).CopyTo(temp);
                    result[i] = BinaryPrimitives.ReadUInt32LittleEndian(temp);
                }
                else
                {
                    result[i] = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(byteOffset));
                }
            }

            return result;
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteUInt32ToBytes(uint value, Span<byte> output)
        {
            output[0] = (byte) value;
            output[1] = (byte) (value >> 8);
            output[2] = (byte) (value >> 16);
            output[3] = (byte) (value >> 24);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteUInt32ToBytes(uint value, byte[] output, int offset)
        {
            output[offset] = (byte) value;
            output[offset + 1] = (byte) (value >> 8);
            output[offset + 2] = (byte) (value >> 16);
            output[offset + 3] = (byte) (value >> 24);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void WriteUInt32ToTag(uint value, byte[] tag, int offset)
        {
            tag[offset] = (byte) value;
            tag[offset + 1] = (byte) (value >> 8);
            tag[offset + 2] = (byte) (value >> 16);
            tag[offset + 3] = (byte) (value >> 24);
        }
        private static uint ReverseUInt32(uint value)
        {
            return BinaryPrimitives.ReverseEndianness(value);
        }
        public static ulong[] MassageToUInt64Array(ReadOnlySpan<byte> data, int offset, int count)
        {
            int ulongCount = (count + 7) / 8;
            ulong[] result = new ulong[ulongCount];

            for ( int i = 0; i < ulongCount; i++ )
            {
                int byteOffset = offset + (i * 8);
                int remainingBytes = Math.Min(8, count - (i * 8));

                if ( remainingBytes < 8 )
                {
                    Span<byte> temp = stackalloc byte[8];
                    data.Slice(byteOffset, remainingBytes).CopyTo(temp);
                    result[i] = BinaryPrimitives.ReadUInt64LittleEndian(temp);
                }
                else
                {
                    result[i] = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(byteOffset));
                }
            }

            return result;
        }

        public static void WriteUInt64ToBytes(ulong value, Span<byte> destination)
        {
            if ( !IsLittleEndian )
            {
                value = ReverseUInt64(value);
            }
            BinaryPrimitives.WriteUInt64LittleEndian(destination, value);
        }

        private static ulong ReverseUInt64(ulong value)
        {
            return BinaryPrimitives.ReverseEndianness(value);
        }
        public static void MassageUInt64Array(Span<ulong> data)
        {
            if ( IsLittleEndian ) return; // No conversion needed for little-endian systems

            for ( int i = 0; i < data.Length; i++ )
            {
                data[i] = ReverseUInt64(data[i]);
            }
        }
    }
}
