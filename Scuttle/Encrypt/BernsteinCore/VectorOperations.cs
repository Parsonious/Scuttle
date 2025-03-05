using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics.Arm;
using Scuttle.Helpers;

namespace Scuttle.Encrypt.BernsteinCore
{
    internal static class VectorOperations
    {
        // Store Vector128<uint> to byte span (handles endianness)
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void StoreVector128(Vector128<uint> vector, Span<byte> output)
        {
            if ( BitConverter.IsLittleEndian )
            {
                // Direct store for little-endian
                MemoryMarshal.Cast<byte, uint>(output)[0] = vector.GetElement(0);
                MemoryMarshal.Cast<byte, uint>(output)[1] = vector.GetElement(1);
                MemoryMarshal.Cast<byte, uint>(output)[2] = vector.GetElement(2);
                MemoryMarshal.Cast<byte, uint>(output)[3] = vector.GetElement(3);
            }
            else
            {
                // Handle big-endian by swapping bytes
                EndianHelper.WriteUInt32ToBytes(vector.GetElement(0), output.Slice(0, 4));
                EndianHelper.WriteUInt32ToBytes(vector.GetElement(1), output.Slice(4, 4));
                EndianHelper.WriteUInt32ToBytes(vector.GetElement(2), output.Slice(8, 4));
                EndianHelper.WriteUInt32ToBytes(vector.GetElement(3), output.Slice(12, 4));
            }
        }
        // Store a Vector128<uint> to a byte span with endianness handling for ARM
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void StoreVector128AdvSimd(Vector128<uint> vector, Span<byte> output)
        {
            if ( BitConverter.IsLittleEndian )
            {
                // Direct store for little-endian
                MemoryMarshal.Cast<byte, uint>(output)[0] = vector.GetElement(0);
                MemoryMarshal.Cast<byte, uint>(output)[1] = vector.GetElement(1);
                MemoryMarshal.Cast<byte, uint>(output)[2] = vector.GetElement(2);
                MemoryMarshal.Cast<byte, uint>(output)[3] = vector.GetElement(3);
            }
            else
            {
                // Handle big-endian by swapping bytes
                Span<uint> temp = stackalloc uint[4];
                temp[0] = vector.GetElement(0);
                temp[1] = vector.GetElement(1);
                temp[2] = vector.GetElement(2);
                temp[3] = vector.GetElement(3);

                for ( int i = 0; i < 4; i++ )
                {
                    EndianHelper.WriteUInt32ToBytes(temp[i], output.Slice(i * 4, 4));
                }
            }
        }
        // Apply XOR operation using SSE2 instructions
        [MethodImpl(MethodImplOptions.AggressiveInlining)]  
        public static void ApplyXorSse2(ReadOnlySpan<byte> input, ReadOnlySpan<byte> keyStream, Span<byte> output)
        {
            int vectorSize = Vector128<byte>.Count;
            int vectorizedLength = input.Length - (input.Length % vectorSize);

            // Process vectors
            for ( int i = 0; i < vectorizedLength; i += vectorSize )
            {
                var inputVector = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(input.Slice(i)));
                var keyStreamVector = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(keyStream.Slice(i)));
                var resultVector = Sse2.Xor(inputVector, keyStreamVector);
                resultVector.StoreUnsafe(ref MemoryMarshal.GetReference(output.Slice(i)));
            }

            // Process remaining bytes
            for ( int i = vectorizedLength; i < input.Length; i++ )
            {
                output[i] = (byte) (input[i] ^ keyStream[i]);
            }
        }
        // Apply XOR operation using ARM AdvSimd instructions
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ApplyXorAdvSimd(ReadOnlySpan<byte> input, ReadOnlySpan<byte> keyStream, Span<byte> output)
        {
            int vectorSize = Vector128<byte>.Count;
            int vectorizedLength = input.Length - (input.Length % vectorSize);

            // Process vectors
            for ( int i = 0; i < vectorizedLength; i += vectorSize )
            {
                var inputVector = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(input.Slice(i)));
                var keyStreamVector = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(keyStream.Slice(i)));
                var resultVector = AdvSimd.Xor(inputVector, keyStreamVector);
                resultVector.StoreUnsafe(ref MemoryMarshal.GetReference(output.Slice(i)));
            }

            // Process remaining bytes
            for ( int i = vectorizedLength; i < input.Length; i++ )
            {
                output[i] = (byte) (input[i] ^ keyStream[i]);
            }
        }
        // Apply XOR operation using scalar instructions (fallback)
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ApplyXorFallback(ReadOnlySpan<byte> input, ReadOnlySpan<byte> keyStream, Span<byte> output)
        {
            for ( int i = 0; i < input.Length; i++ )
            {
                output[i] = (byte) (input[i] ^ keyStream[i]);
            }
        }
    }
}