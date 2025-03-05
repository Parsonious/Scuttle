using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using System.Numerics;
using Scuttle.Interfaces;
using Scuttle.Base;
using Scuttle.Helpers;
using Scuttle.Encrypt.ChaChaCore;

namespace Scuttle.Encrypt
{
    internal class ChaCha20Encrypt : BaseEncryption
    {
        private const int KeySize = 32;    // 256 bits
        private const int NonceSize = 12;  // 96 bits
        private const int BlockSize = 64;  // ChaCha20 block size
        private const int TagSize = 16;    // Poly1305 tag size

        // Static constants for better performance
        private static readonly uint[] ChaChaConstants = {
            0x61707865, 0x3320646E, 0x79622D32, 0x6B206574
        };

        public ChaCha20Encrypt(IEncoder encoder) : base(encoder) { }

        public override byte[] Encrypt(byte[] data, byte[] key)
        {
            if ( data == null || data.Length == 0 )
                throw new ArgumentException("Data cannot be null or empty.", nameof(data));
            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));

            // Use ArrayPool for better memory management
            byte[] nonce = ArrayPool<byte>.Shared.Rent(NonceSize);
            byte[] ciphertext = ArrayPool<byte>.Shared.Rent(data.Length);

            try
            {
                RandomNumberGenerator.Fill(nonce.AsSpan(0, NonceSize));

                // Generate keystream and encrypt data
                EncryptWithKeyStream(data, key, nonce.AsSpan(0, NonceSize), ciphertext);

                // Calculate Poly1305 auth tag
                byte[] poly1305Key = GenerateKeyStream(key, nonce.AsSpan(0, NonceSize), KeySize);
                byte[] tag = Poly1305.ComputeTag(poly1305Key, ciphertext.AsSpan(0, data.Length));

                // Combine nonce, ciphertext, and tag
                byte[] result = new byte[NonceSize + data.Length + TagSize];
                Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
                Buffer.BlockCopy(ciphertext, 0, result, NonceSize, data.Length);
                Buffer.BlockCopy(tag, 0, result, NonceSize + data.Length, TagSize);

                return result;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(nonce);
                ArrayPool<byte>.Shared.Return(ciphertext);
            }
        }

        public override byte[] Decrypt(byte[] encryptedData, byte[] key)
        {
            if ( encryptedData == null || encryptedData.Length < NonceSize + TagSize )
                throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));

            // Calculate sizes
            int ciphertextLength = encryptedData.Length - NonceSize - TagSize;

            // Use span slices to avoid unnecessary allocations
            ReadOnlySpan<byte> nonceSpan = encryptedData.AsSpan(0, NonceSize);
            ReadOnlySpan<byte> ciphertextSpan = encryptedData.AsSpan(NonceSize, ciphertextLength);
            ReadOnlySpan<byte> tagSpan = encryptedData.AsSpan(NonceSize + ciphertextLength, TagSize);

            // Verify MAC
            byte[] poly1305Key = GenerateKeyStream(key, nonceSpan, KeySize);
            byte[] computedTag = Poly1305.ComputeTag(poly1305Key, ciphertextSpan);

            if ( !ChaChaUtils.ConstantTimeEquals(tagSpan, computedTag.AsSpan()) )
                throw new CryptographicException("Authentication failed.");

            // Decrypt data
            byte[] plaintext = new byte[ciphertextLength];

            // Generate keystream and decrypt in a single operation
            DecryptWithKeyStream(ciphertextSpan, key, nonceSpan, plaintext);

            return plaintext;
        }

        // Optimized keystream generation with SIMD support when available
        private byte[] GenerateKeyStream(byte[] key, ReadOnlySpan<byte> nonce, int length)
        {
            byte[] keyStream = new byte[length];

            if ( Sse2.IsSupported && length >= Vector128<byte>.Count * 4 )
            {
                GenerateKeyStreamSse2(key, nonce, keyStream);
            }
            else if ( AdvSimd.IsSupported && length >= Vector128<byte>.Count * 4 )
            {
                GenerateKeyStreamAdvSimd(key, nonce, keyStream);
            }
            else
            {
                GenerateKeyStreamFallback(key, nonce, keyStream);
            }

            return keyStream;
        }

        // SSE2 optimized keystream generation
        private void GenerateKeyStreamSse2(byte[] key, ReadOnlySpan<byte> nonce, Span<byte> keyStream)
        {
            // Prepare state
            Span<uint> initialState = stackalloc uint[16];

            // Initialize constants
            initialState[0] = ChaChaConstants[0];
            initialState[1] = ChaChaConstants[1];
            initialState[2] = ChaChaConstants[2];
            initialState[3] = ChaChaConstants[3];

            // Set key
            var keyUints = EndianHelper.MassageToUInt32Array(key, 0, key.Length);
            keyUints.AsSpan().CopyTo(initialState.Slice(4, 8));

            // Initialize counter to 0
            initialState[12] = 0;

            // Set nonce
            var nonceUints = EndianHelper.MassageToUInt32Array(nonce, 0, nonce.Length);
            nonceUints.AsSpan().CopyTo(initialState.Slice(13, 3));

            // Process blocks using SIMD
            int position = 0;
            uint counter = 0;

            while ( position < keyStream.Length )
            {
                // Update counter for this block
                initialState[12] = counter++;

                // Load state into SSE2 registers
                Vector128<uint>[] state = new Vector128<uint>[4];
                state[0] = Vector128.Create(initialState[0], initialState[1], initialState[2], initialState[3]);
                state[1] = Vector128.Create(initialState[4], initialState[5], initialState[6], initialState[7]);
                state[2] = Vector128.Create(initialState[8], initialState[9], initialState[10], initialState[11]);
                state[3] = Vector128.Create(initialState[12], initialState[13], initialState[14], initialState[15]);

                // Create working copy
                Vector128<uint>[] working = new Vector128<uint>[4];
                state.CopyTo(working, 0);

                // Perform ChaCha20 rounds using SIMD
                for ( int i = 0; i < 10; i++ )
                {
                    ChaChaUtils.ChaChaRoundSse2(ref working[0], ref working[1], ref working[2], ref working[3]);
                }

                // Add original state to working state
                working[0] = Sse2.Add(working[0], state[0]);
                working[1] = Sse2.Add(working[1], state[1]);
                working[2] = Sse2.Add(working[2], state[2]);
                working[3] = Sse2.Add(working[3], state[3]);

                // Convert to bytes and copy to keystream
                byte[] blockBytes = new byte[BlockSize];

                // Store SIMD vectors to bytes with proper endianness
                StoreVector128(working[0], blockBytes.AsSpan(0));
                StoreVector128(working[1], blockBytes.AsSpan(16));
                StoreVector128(working[2], blockBytes.AsSpan(32));
                StoreVector128(working[3], blockBytes.AsSpan(48));

                // Copy to output
                int bytesToCopy = Math.Min(BlockSize, keyStream.Length - position);
                blockBytes.AsSpan(0, bytesToCopy).CopyTo(keyStream.Slice(position, bytesToCopy));
                position += bytesToCopy;
            }
        }

        // Store a Vector128<uint> to a byte span with endianness handling
        private void StoreVector128(Vector128<uint> vector, Span<byte> output)
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

        // ARM NEON implementation for keystream generation
        private void GenerateKeyStreamAdvSimd(byte[] key, ReadOnlySpan<byte> nonce, Span<byte> keyStream)
        {
            // Prepare state
            Span<uint> initialState = stackalloc uint[16];

            // Initialize constants
            initialState[0] = ChaChaConstants[0];
            initialState[1] = ChaChaConstants[1];
            initialState[2] = ChaChaConstants[2];
            initialState[3] = ChaChaConstants[3];

            // Set key
            var keyUints = EndianHelper.MassageToUInt32Array(key, 0, key.Length);
            keyUints.AsSpan().CopyTo(initialState.Slice(4, 8));

            // Initialize counter to 0
            initialState[12] = 0;

            // Set nonce
            var nonceUints = EndianHelper.MassageToUInt32Array(nonce, 0, nonce.Length);
            nonceUints.AsSpan().CopyTo(initialState.Slice(13, 3));

            // Process blocks using ARM NEON
            int position = 0;
            uint counter = 0;

            while ( position < keyStream.Length )
            {
                // Update counter for this block
                initialState[12] = counter++;

                // Load state into AdvSimd registers
                Vector128<uint>[] state = new Vector128<uint>[4];
                state[0] = Vector128.Create(initialState[0], initialState[1], initialState[2], initialState[3]);
                state[1] = Vector128.Create(initialState[4], initialState[5], initialState[6], initialState[7]);
                state[2] = Vector128.Create(initialState[8], initialState[9], initialState[10], initialState[11]);
                state[3] = Vector128.Create(initialState[12], initialState[13], initialState[14], initialState[15]);

                // Create working copy
                Vector128<uint>[] working = new Vector128<uint>[4];
                state.CopyTo(working, 0);

                // Perform ChaCha20 rounds using ARM NEON
                for ( int i = 0; i < 10; i++ )
                {
                    ChaChaUtils.ChaChaRoundAdvSimd(ref working[0], ref working[1], ref working[2], ref working[3]);
                }

                // Add original state to working state
                working[0] = AdvSimd.Add(working[0].AsUInt32(), state[0].AsUInt32()).AsUInt32();
                working[1] = AdvSimd.Add(working[1].AsUInt32(), state[1].AsUInt32()).AsUInt32();
                working[2] = AdvSimd.Add(working[2].AsUInt32(), state[2].AsUInt32()).AsUInt32();
                working[3] = AdvSimd.Add(working[3].AsUInt32(), state[3].AsUInt32()).AsUInt32();

                // Convert to bytes and copy to keystream
                byte[] blockBytes = new byte[BlockSize];

                // Store vectors to bytes with proper endianness
                StoreVector128AdvSimd(working[0], blockBytes.AsSpan(0));
                StoreVector128AdvSimd(working[1], blockBytes.AsSpan(16));
                StoreVector128AdvSimd(working[2], blockBytes.AsSpan(32));
                StoreVector128AdvSimd(working[3], blockBytes.AsSpan(48));

                // Copy to output
                int bytesToCopy = Math.Min(BlockSize, keyStream.Length - position);
                blockBytes.AsSpan(0, bytesToCopy).CopyTo(keyStream.Slice(position, bytesToCopy));
                position += bytesToCopy;
            }
        }

        // Store a Vector128<uint> to a byte span with endianness handling for ARM
        private void StoreVector128AdvSimd(Vector128<uint> vector, Span<byte> output)
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

        // Fallback scalar implementation
        private void GenerateKeyStreamFallback(byte[] key, ReadOnlySpan<byte> nonce, Span<byte> keyStream)
        {
            Span<uint> state = stackalloc uint[16];

            // Initialize state constants
            state[0] = ChaChaConstants[0];
            state[1] = ChaChaConstants[1];
            state[2] = ChaChaConstants[2];
            state[3] = ChaChaConstants[3];

            // Set key
            var keyUints = EndianHelper.MassageToUInt32Array(key, 0, key.Length);
            keyUints.AsSpan().CopyTo(state.Slice(4, 8));

            // Initialize counter to 0
            state[12] = 0;

            // Set nonce
            var nonceUints = EndianHelper.MassageToUInt32Array(nonce, 0, nonce.Length);
            nonceUints.AsSpan().CopyTo(state.Slice(13, 3));

            // Process blocks
            int position = 0;
            Span<uint> working = stackalloc uint[16];
            Span<byte> block = stackalloc byte[BlockSize];

            while ( position < keyStream.Length )
            {
                // Copy state to working buffer
                state.CopyTo(working);

                // Perform ChaCha20 block function
                for ( int i = 0; i < 10; i++ )
                {
                    // Column rounds
                    ChaChaUtils.QuarterRound(ref working[0], ref working[4], ref working[8], ref working[12]);
                    ChaChaUtils.QuarterRound(ref working[1], ref working[5], ref working[9], ref working[13]);
                    ChaChaUtils.QuarterRound(ref working[2], ref working[6], ref working[10], ref working[14]);
                    ChaChaUtils.QuarterRound(ref working[3], ref working[7], ref working[11], ref working[15]);

                    // Diagonal rounds
                    ChaChaUtils.QuarterRound(ref working[0], ref working[5], ref working[10], ref working[15]);
                    ChaChaUtils.QuarterRound(ref working[1], ref working[6], ref working[11], ref working[12]);
                    ChaChaUtils.QuarterRound(ref working[2], ref working[7], ref working[8], ref working[13]);
                    ChaChaUtils.QuarterRound(ref working[3], ref working[4], ref working[9], ref working[14]);
                }

                // Add original state back to working state
                for ( int i = 0; i < 16; i++ )
                {
                    working[i] += state[i];
                }

                // Convert to bytes
                for ( int i = 0; i < 16; i++ )
                {
                    EndianHelper.WriteUInt32ToBytes(working[i], block.Slice(i * 4, 4));
                }

                // Copy to output
                int bytesToCopy = Math.Min(BlockSize, keyStream.Length - position);
                block.Slice(0, bytesToCopy).CopyTo(keyStream.Slice(position, bytesToCopy));
                position += bytesToCopy;

                // Increment counter for next block
                if ( ++state[12] == 0 )
                {
                    // Handle overflow
                    state[13]++;
                }
            }
        }
        // Encrypt data with keystream in a single operation
        private void EncryptWithKeyStream(ReadOnlySpan<byte> plaintext, byte[] key, ReadOnlySpan<byte> nonce, Span<byte> ciphertext)
        {
            // Initialize state
            Span<uint> state = stackalloc uint[16];

            // Initialize constants
            state[0] = ChaChaConstants[0];
            state[1] = ChaChaConstants[1];
            state[2] = ChaChaConstants[2];
            state[3] = ChaChaConstants[3];

            // Set key
            var keyUints = EndianHelper.MassageToUInt32Array(key, 0, key.Length);
            keyUints.AsSpan().CopyTo(state.Slice(4, 8));

            // Initialize counter to 0
            state[12] = 0;

            // Set nonce
            var nonceUints = EndianHelper.MassageToUInt32Array(nonce, 0, nonce.Length);
            nonceUints.AsSpan().CopyTo(state.Slice(13, 3));

            // Process blocks in chunks for better cache locality
            const int chunkSize = 16 * 1024; // 16KB chunks
            for ( int offset = 0; offset < plaintext.Length; offset += chunkSize )
            {
                int currentChunkSize = Math.Min(chunkSize, plaintext.Length - offset);
                EncryptChunk(
                    plaintext.Slice(offset, currentChunkSize),
                    state,
                    ciphertext.Slice(offset, currentChunkSize)
                );
            }
        }

        // Encrypt a chunk of data
        private void EncryptChunk(ReadOnlySpan<byte> plainChunk, Span<uint> initialState, Span<byte> cipherChunk)
        {
            int position = 0;
            Span<uint> working = stackalloc uint[16];
            Span<byte> keyStreamBlock = stackalloc byte[BlockSize];

            while ( position < plainChunk.Length )
            {
                // Copy state to working buffer
                initialState.CopyTo(working);

                // Perform ChaCha20 block function
                for ( int i = 0; i < 10; i++ )
                {
                    // Unrolled column and diagonal rounds
                    ChaChaUtils.QuarterRound(ref working[0], ref working[4], ref working[8], ref working[12]);
                    ChaChaUtils.QuarterRound(ref working[1], ref working[5], ref working[9], ref working[13]);
                    ChaChaUtils.QuarterRound(ref working[2], ref working[6], ref working[10], ref working[14]);
                    ChaChaUtils.QuarterRound(ref working[3], ref working[7], ref working[11], ref working[15]);

                    ChaChaUtils.QuarterRound(ref working[0], ref working[5], ref working[10], ref working[15]);
                    ChaChaUtils.QuarterRound(ref working[1], ref working[6], ref working[11], ref working[12]);
                    ChaChaUtils.QuarterRound(ref working[2], ref working[7], ref working[8], ref working[13]);
                    ChaChaUtils.QuarterRound(ref working[3], ref working[4], ref working[9], ref working[14]);
                }

                // Add state to working state and convert to bytes
                for ( int i = 0; i < 16; i++ )
                {
                    working[i] += initialState[i];
                    EndianHelper.WriteUInt32ToBytes(working[i], keyStreamBlock.Slice(i * 4, 4));
                }

                // XOR with plaintext to produce ciphertext
                int bytesToProcess = Math.Min(BlockSize, plainChunk.Length - position);
                for ( int i = 0; i < bytesToProcess; i++ )
                {
                    cipherChunk[position + i] = (byte) (plainChunk[position + i] ^ keyStreamBlock[i]);
                }

                position += bytesToProcess;
                initialState[12]++; // Increment counter for next block
                if ( initialState[12] == 0 ) // Handle overflow
                {
                    initialState[13]++;
                }
            }
        }

        // Decrypt data with keystream
        private void DecryptWithKeyStream(ReadOnlySpan<byte> ciphertext, byte[] key, ReadOnlySpan<byte> nonce, Span<byte> plaintext)
        {
            // Decryption is the same as encryption in stream ciphers
            EncryptWithKeyStream(ciphertext, key, nonce, plaintext);
        }
        public override byte[] GenerateKey()
        {
            byte[] key = new byte[KeySize];
            RandomNumberGenerator.Fill(key);
            return key;
        }
    }
}

