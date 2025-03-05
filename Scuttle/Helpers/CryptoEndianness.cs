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

                // Copy first half of key
                keyWords1.AsSpan().CopyTo(state.Slice(1, 4));
                // Copy second half of key
                keyWords2.AsSpan().CopyTo(state.Slice(11, 4));
            }
            else
            {
                state[0] = CHACHA_CONST_0;
                state[1] = CHACHA_CONST_1;
                state[2] = CHACHA_CONST_2;
                state[3] = CHACHA_CONST_3;

                // For ChaCha20, handle the key as one 256-bit piece
                var keyWords = EndianHelper.MassageToUInt32Array(key, 0, key.Length);
                keyWords.AsSpan().CopyTo(state.Slice(4, 8));
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
                nonceWords.AsSpan().CopyTo(state.Slice(13, 3));
            }
        }


        // ThreeFish Methods
        public static void InitializeThreeFishState(Span<ulong> state, ReadOnlySpan<byte> input, ReadOnlySpan<byte> tweak)
        {
            // Ensure state array is large enough
            if ( state.Length < 8 )
                throw new ArgumentException("State array must be at least 8 elements", nameof(state));

            // Convert input to 64-bit words with proper endianness (exactly 8 words for ThreeFish-512)
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


        // Common block processing methods
        public static void ProcessBlock32(Span<byte> output, ReadOnlySpan<uint> state)
        {
            for ( int i = 0; i < state.Length; i++ )
            {
                EndianHelper.WriteUInt32ToBytes(state[i], output.Slice(i * 4, 4));
            }
        }

        public static void ProcessBlock64(Span<byte> output, ReadOnlySpan<ulong> state)
        {
            for ( int i = 0; i < state.Length; i++ )
            {
                EndianHelper.WriteUInt64ToBytes(state[i], output.Slice(i * 8, 8));
            }
        }

        // MAC operations
        public static void ProcessMAC(Span<byte> tag, uint h0, uint h1, uint h2, uint h3)
        {
            EndianHelper.WriteUInt32ToBytes(h0, tag[..4]);
            EndianHelper.WriteUInt32ToBytes(h1, tag.Slice(4, 4));
            EndianHelper.WriteUInt32ToBytes(h2, tag.Slice(8, 4));
            EndianHelper.WriteUInt32ToBytes(h3, tag.Slice(12, 4));
        }

        // Utility methods for rotations
        public static uint RotateLeft32(uint value, int offset)
            => (value << offset) | (value >> (32 - offset));

        public static ulong RotateLeft64(ulong value, int offset)
            => (value << offset) | (value >> (64 - offset));
    }
}