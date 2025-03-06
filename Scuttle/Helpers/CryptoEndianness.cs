using System.Runtime.CompilerServices;

namespace Scuttle.Helpers
{
    internal static class CryptoEndianness
    {
        // Common constants
        private const uint CHACHA_CONST_0 = 0x61707865; // "expa"
        private const uint CHACHA_CONST_1 = 0x3320646E; // "nd 3"
        private const uint CHACHA_CONST_2 = 0x79622D32; // "2-by"
        private const uint CHACHA_CONST_3 = 0x6B206574; // "te k"
        private const ulong THREEFISH_CONST = 0x1BD11BDAA9FC1A22;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void InitializeChaChaState(Span<uint> state, ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce, uint counter = 0, bool isSalsa = false)
        {
            // Initialize constants based on algorithm
            if ( isSalsa )
            {
                state[0] = CHACHA_CONST_0;
                state[5] = CHACHA_CONST_1;
                state[10] = CHACHA_CONST_2;
                state[15] = CHACHA_CONST_3;

                // For Salsa20, handle 256-bit key as two 128-bit parts
                var keyWords1 = EndianHelper.MassageToUInt32Array(key[..16], 0, 16); // First 16 bytes
                var keyWords2 = EndianHelper.MassageToUInt32Array(key[16..], 0, 16); // Second 16 bytes

                // Copy first half of key (unroll for potential JIT optimization)
                state[1] = keyWords1[0];
                state[2] = keyWords1[1];
                state[3] = keyWords1[2];
                state[4] = keyWords1[3];

                // Copy second half of key
                state[11] = keyWords2[0];
                state[12] = keyWords2[1];
                state[13] = keyWords2[2];
                state[14] = keyWords2[3];
            }
            else
            {
                state[0] = CHACHA_CONST_0;
                state[1] = CHACHA_CONST_1;
                state[2] = CHACHA_CONST_2;
                state[3] = CHACHA_CONST_3;

                // For ChaCha20, handle the key as one 256-bit piece
                var keyWords = EndianHelper.MassageToUInt32Array(key, 0, key.Length);

                // Unroll loop for potential JIT optimization
                state[4] = keyWords[0];
                state[5] = keyWords[1];
                state[6] = keyWords[2];
                state[7] = keyWords[3];
                state[8] = keyWords[4];
                state[9] = keyWords[5];
                state[10] = keyWords[6];
                state[11] = keyWords[7];
            }

            // Set counter and nonce
            if ( isSalsa )
            {
                state[8] = counter;
                state[6] = EndianHelper.MassageToUInt32Array(nonce, 0, 4)[0];
                state[7] = EndianHelper.MassageToUInt32Array(nonce, 4, 4)[0];
            }
            else
            {
                state[12] = counter;
                var nonceWords = EndianHelper.MassageToUInt32Array(nonce, 0, nonce.Length);

                // Unroll loop for potential JIT optimization
                state[13] = nonceWords[0];
                state[14] = nonceWords[1];
                state[15] = nonceWords[2];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void InitializeThreeFishState(Span<ulong> state, ReadOnlySpan<byte> input, ReadOnlySpan<byte> tweak)
        {
            // Ensure state array is large enough
            if ( state.Length < 8 )
                throw new ArgumentException("State array must be at least 8 elements", nameof(state));

            // Optimized approach for directly reading ulong values
            for ( int i = 0; i < 8; i++ )
            {
                var slice = input.Slice(i * 8, 8);
                state[i] = EndianHelper.MassageToUInt64Array(slice, 0, 8)[0];
            }

            // Process tweak if provided
            if ( !tweak.IsEmpty )
            {
                var tweakWords = EndianHelper.MassageToUInt64Array(tweak, 0, tweak.Length);
                if ( state.Length > 8 )  // Only if we have space for tweak values
                {
                    state[8] = tweakWords[0];
                    state[9] = tweakWords[1];
                    state[10] = tweakWords[0] ^ tweakWords[1];
                    state[11] = THREEFISH_CONST;
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ProcessBlock32(Span<byte> output, ReadOnlySpan<uint> state)
        {
            for ( int i = 0; i < state.Length; i++ )
            {
                EndianHelper.WriteUInt32ToBytes(state[i], output.Slice(i * 4, 4));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ProcessBlock64(Span<byte> output, ReadOnlySpan<ulong> state)
        {
            for ( int i = 0; i < state.Length; i++ )
            {
                EndianHelper.WriteUInt64ToBytes(state[i], output.Slice(i * 8, 8));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ProcessMAC(Span<byte> tag, uint h0, uint h1, uint h2, uint h3)
        {
            EndianHelper.WriteUInt32ToBytes(h0, tag[..4]);
            EndianHelper.WriteUInt32ToBytes(h1, tag.Slice(4, 4));
            EndianHelper.WriteUInt32ToBytes(h2, tag.Slice(8, 4));
            EndianHelper.WriteUInt32ToBytes(h3, tag.Slice(12, 4));
        }

        // Utility methods for rotations - optimized with AggressiveInlining
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint RotateLeft32(uint value, int offset)
            => (value << offset) | (value >> (32 - offset));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong RotateLeft64(ulong value, int offset)
            => (value << offset) | (value >> (64 - offset));
    }
}
