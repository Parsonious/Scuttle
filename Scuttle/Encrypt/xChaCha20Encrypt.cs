using System.Buffers;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;
using Scuttle.Interfaces;
using Scuttle.Base;
using Scuttle.Encrypt.ChaChaCore;
using Scuttle.Helpers;

namespace Scuttle.Encrypt
{
    internal class XChaCha20Encrypt : BaseEncryption
    {
        private const int KeySize = ChaChaConstants.KeySize;     // 256 bits
        private const int NonceSize = ChaChaConstants.XChaCha20NonceSize;   // 192 bits for XChaCha20
        private const int ChaChaBlockSize = ChaChaConstants.BlockSize;  // ChaCha20 block size
        private const int TagSize = ChaChaConstants.TagSize;     // 128 bits for Poly1305
        private const int HChaChaRounds = 20; // Rounds for HChaCha20 function

        public XChaCha20Encrypt(IEncoder encoder) : base(encoder) { }

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
                // Fill nonce with random data
                RandomNumberGenerator.Fill(nonce.AsSpan(0, NonceSize));

                // Derive the subkey and subnonce using HChaCha20
                byte[] subkey = HChaCha20(key, nonce.AsSpan(0, 16));

                // Encrypt data with derived subkey and remaining nonce bytes
                EncryptWithKeyStream(data, subkey, nonce.AsSpan(16, 8), ciphertext);

                // Calculate Poly1305 auth tag
                byte[] poly1305Key = GenerateKeyStream(subkey, nonce.AsSpan(16, 8), 32);
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
                // Return borrowed arrays to the pool
                ArrayPool<byte>.Shared.Return(nonce);
                ArrayPool<byte>.Shared.Return(ciphertext);
            }
        }

        public override byte[] Decrypt(byte[] encryptedData, byte[] key)
        {
            if ( encryptedData == null || encryptedData.Length < NonceSize + TagSize )
                throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));

            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));

            // Extract nonce and ciphertext data
            ReadOnlySpan<byte> nonceSpan = encryptedData.AsSpan(0, NonceSize);
            int ciphertextLength = encryptedData.Length - NonceSize - TagSize;
            ReadOnlySpan<byte> ciphertextSpan = encryptedData.AsSpan(NonceSize, ciphertextLength);
            ReadOnlySpan<byte> tagSpan = encryptedData.AsSpan(NonceSize + ciphertextLength, TagSize);

            // Derive the subkey using HChaCha20
            byte[] subkey = HChaCha20(key, nonceSpan.Slice(0, 16));

            // Calculate and verify Poly1305 auth tag
            byte[] poly1305Key = GenerateKeyStream(subkey, nonceSpan.Slice(16, 8), 32);
            byte[] computedTag = Poly1305.ComputeTag(poly1305Key, ciphertextSpan);

            if ( !ChaChaUtils.ConstantTimeEquals(tagSpan, computedTag.AsSpan()) )
                throw new CryptographicException("Authentication failed.");

            // Decrypt data
            byte[] plaintext = new byte[ciphertextLength];
            DecryptWithKeyStream(ciphertextSpan, subkey, nonceSpan.Slice(16, 8), plaintext);

            return plaintext;
        }

        // HChaCha20 function to derive subkey from key and first 16 bytes of nonce
        private byte[] HChaCha20(byte[] key, ReadOnlySpan<byte> nonce)
        {
            // Initialize state for HChaCha20
            Span<uint> state = stackalloc uint[16];

            // Set up the state with ChaCha constants, key, and nonce
            state[0] = ChaChaConstants.StateConstants[0];
            state[1] = ChaChaConstants.StateConstants[1];
            state[2] = ChaChaConstants.StateConstants[2];
            state[3] = ChaChaConstants.StateConstants[3];

            // Copy the key into state (words 4-11)
            for ( int i = 0; i < 8; i++ )
            {
                state[4 + i] = BitConverter.ToUInt32(key.AsSpan(i * 4, 4));
            }

            // Copy nonce into state (words 12-15)
            for ( int i = 0; i < 4; i++ )
            {
                state[12 + i] = BitConverter.ToUInt32(nonce.Slice(i * 4, 4));
            }

            // Apply the ChaCha rounds
            Span<uint> workingState = stackalloc uint[16];
            state.CopyTo(workingState);

            for ( int i = 0; i < HChaChaRounds; i += 2 )
            {
                // Column rounds
                ChaChaUtils.QuarterRound(ref workingState[0], ref workingState[4], ref workingState[8], ref workingState[12]);
                ChaChaUtils.QuarterRound(ref workingState[1], ref workingState[5], ref workingState[9], ref workingState[13]);
                ChaChaUtils.QuarterRound(ref workingState[2], ref workingState[6], ref workingState[10], ref workingState[14]);
                ChaChaUtils.QuarterRound(ref workingState[3], ref workingState[7], ref workingState[11], ref workingState[15]);

                // Diagonal rounds
                ChaChaUtils.QuarterRound(ref workingState[0], ref workingState[5], ref workingState[10], ref workingState[15]);
                ChaChaUtils.QuarterRound(ref workingState[1], ref workingState[6], ref workingState[11], ref workingState[12]);
                ChaChaUtils.QuarterRound(ref workingState[2], ref workingState[7], ref workingState[8], ref workingState[13]);
                ChaChaUtils.QuarterRound(ref workingState[3], ref workingState[4], ref workingState[9], ref workingState[14]);
            }

            // Extract subkey (first 4 words and last 4 words of the state)
            byte[] subkey = new byte[32];

            EndianHelper.WriteUInt32ToBytes(workingState[0], subkey, 0);
            EndianHelper.WriteUInt32ToBytes(workingState[1], subkey, 4);
            EndianHelper.WriteUInt32ToBytes(workingState[2], subkey, 8);
            EndianHelper.WriteUInt32ToBytes(workingState[3], subkey, 12);

            EndianHelper.WriteUInt32ToBytes(workingState[12], subkey, 16);
            EndianHelper.WriteUInt32ToBytes(workingState[13], subkey, 20);
            EndianHelper.WriteUInt32ToBytes(workingState[14], subkey, 24);
            EndianHelper.WriteUInt32ToBytes(workingState[15], subkey, 28);

            return subkey;
        }

        // Generate keystream for encryption/decryption (similar to ChaCha20Encrypt)
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

        // Encrypt data with keystream in a single operation
        private void EncryptWithKeyStream(ReadOnlySpan<byte> plaintext, byte[] key, ReadOnlySpan<byte> nonce, Span<byte> ciphertext)
        {
            // Initialize state
            Span<uint> state = stackalloc uint[16];

            // Initialize constants
            state[0] = ChaChaConstants.StateConstants[0];
            state[1] = ChaChaConstants.StateConstants[1];
            state[2] = ChaChaConstants.StateConstants[2];
            state[3] = ChaChaConstants.StateConstants[3];

            // Set key
            for ( int i = 0; i < 8; i++ )
            {
                state[4 + i] = BitConverter.ToUInt32(key.AsSpan(i * 4, 4));
            }

            // Initialize counter to 0
            state[12] = 0;

            // Set nonce (the 8 bytes from the XChaCha20 nonce after the 16 bytes used for HChaCha20)
            state[13] = BitConverter.ToUInt32(nonce.Slice(0, 4));
            state[14] = BitConverter.ToUInt32(nonce.Slice(4, 4));
            state[15] = 0; // Last word is zero for XChaCha20

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

        // Decrypt data with keystream
        private void DecryptWithKeyStream(ReadOnlySpan<byte> ciphertext, byte[] key, ReadOnlySpan<byte> nonce, Span<byte> plaintext)
        {
            // Decryption is the same as encryption in stream ciphers
            EncryptWithKeyStream(ciphertext, key, nonce, plaintext);
        }

        // Encrypt a chunk of data
        private void EncryptChunk(ReadOnlySpan<byte> plainChunk, Span<uint> initialState, Span<byte> cipherChunk)
        {
            int position = 0;
            Span<uint> working = stackalloc uint[16];
            Span<byte> keyStreamBlock = stackalloc byte[ChaChaBlockSize];

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
                int bytesToProcess = Math.Min(ChaChaBlockSize, plainChunk.Length - position);
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

        // SSE2 optimized keystream generation
        private void GenerateKeyStreamSse2(byte[] key, ReadOnlySpan<byte> nonce, Span<byte> keyStream)
        {
            // Similar implementation as in ChaCha20Encrypt
            Span<uint> initialState = stackalloc uint[16];

            // Initialize constants
            initialState[0] = ChaChaConstants.StateConstants[0];
            initialState[1] = ChaChaConstants.StateConstants[1];
            initialState[2] = ChaChaConstants.StateConstants[2];
            initialState[3] = ChaChaConstants.StateConstants[3];

            // Set key
            for ( int i = 0; i < 8; i++ )
            {
                initialState[4 + i] = BitConverter.ToUInt32(key.AsSpan(i * 4, 4));
            }

            // Initialize counter to 0
            initialState[12] = 0;

            // Set nonce
            initialState[13] = BitConverter.ToUInt32(nonce.Slice(0, 4));
            initialState[14] = BitConverter.ToUInt32(nonce.Slice(4, 4));
            initialState[15] = 0;

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
                byte[] blockBytes = new byte[ChaChaBlockSize];

                // Store SIMD vectors to bytes with proper endianness
                VectorOperations.StoreVector128(working[0], blockBytes.AsSpan(0));
                VectorOperations.StoreVector128(working[1], blockBytes.AsSpan(16));
                VectorOperations.StoreVector128(working[2], blockBytes.AsSpan(32));
                VectorOperations.StoreVector128(working[3], blockBytes.AsSpan(48));

                // Copy to output
                int bytesToCopy = Math.Min(ChaChaBlockSize, keyStream.Length - position);
                blockBytes.AsSpan(0, bytesToCopy).CopyTo(keyStream.Slice(position, bytesToCopy));
                position += bytesToCopy;
            }
        }

        // ARM NEON implementation for keystream generation
        private void GenerateKeyStreamAdvSimd(byte[] key, ReadOnlySpan<byte> nonce, Span<byte> keyStream)
        {
            // Prepare state
            Span<uint> initialState = stackalloc uint[16];

            // Initialize constants
            initialState[0] = ChaChaConstants.StateConstants[0];
            initialState[1] = ChaChaConstants.StateConstants[1];
            initialState[2] = ChaChaConstants.StateConstants[2];
            initialState[3] = ChaChaConstants.StateConstants[3];

            // Set key
            for ( int i = 0; i < 8; i++ )
            {
                initialState[4 + i] = BitConverter.ToUInt32(key.AsSpan(i * 4, 4));
            }

            // Initialize counter to 0
            initialState[12] = 0;

            // Set nonce
            initialState[13] = BitConverter.ToUInt32(nonce.Slice(0, 4));
            initialState[14] = BitConverter.ToUInt32(nonce.Slice(4, 4));
            initialState[15] = 0;

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
                byte[] blockBytes = new byte[ChaChaBlockSize];

                // Store vectors to bytes with proper endianness
                VectorOperations.StoreVector128AdvSimd(working[0], blockBytes.AsSpan(0));
                VectorOperations.StoreVector128AdvSimd(working[1], blockBytes.AsSpan(16));
                VectorOperations.StoreVector128AdvSimd(working[2], blockBytes.AsSpan(32));
                VectorOperations.StoreVector128AdvSimd(working[3], blockBytes.AsSpan(48));

                // Copy to output
                int bytesToCopy = Math.Min(ChaChaBlockSize, keyStream.Length - position);
                blockBytes.AsSpan(0, bytesToCopy).CopyTo(keyStream.Slice(position, bytesToCopy));
                position += bytesToCopy;
            }
        }

        // Fallback scalar implementation for keystream generation
        private void GenerateKeyStreamFallback(byte[] key, ReadOnlySpan<byte> nonce, Span<byte> keyStream)
        {
            Span<uint> state = stackalloc uint[16];

            // Initialize state constants
            state[0] = ChaChaConstants.StateConstants[0];
            state[1] = ChaChaConstants.StateConstants[1];
            state[2] = ChaChaConstants.StateConstants[2];
            state[3] = ChaChaConstants.StateConstants[3];

            // Set key
            for ( int i = 0; i < 8; i++ )
            {
                state[4 + i] = BitConverter.ToUInt32(key.AsSpan(i * 4, 4));
            }

            // Initialize counter to 0
            state[12] = 0;

            // Set nonce
            state[13] = BitConverter.ToUInt32(nonce.Slice(0, 4));
            state[14] = BitConverter.ToUInt32(nonce.Slice(4, 4));
            state[15] = 0;

            // Process blocks
            int position = 0;
            Span<uint> working = stackalloc uint[16];
            Span<byte> block = stackalloc byte[ChaChaBlockSize];

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
                int bytesToCopy = Math.Min(ChaChaBlockSize, keyStream.Length - position);
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

        // Generate a random key suitable for XChaCha20-Poly1305
        public override byte[] GenerateKey()
        {
            // Create a secure random key of appropriate size
            byte[] key = new byte[KeySize];
            RandomNumberGenerator.Fill(key);
            return key;
        }
    }
}
