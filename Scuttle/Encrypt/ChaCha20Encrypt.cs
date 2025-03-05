using System.Security.Cryptography;
using Token_Generator.Interfaces;
using Token_Generator.Base;
using Token_Generator.Helpers;

namespace Token_Generator.Encrypt
{
    internal class ChaCha20Encrypt : BaseEncryption
    {
        private const int KeySize = 32;    // 256 bits
        private const int NonceSize = 12;  // 96 bits
        private const int BlockSize = 64;  // ChaCha20 block size
        private const int TagSize = 16;    // Poly1305 tag size


        public ChaCha20Encrypt(IEncoder encoder) : base(encoder) { }

        public override byte[] Encrypt(byte[] data, byte[] key)
        {
            if ( data == null || data.Length == 0 )
                throw new ArgumentException("Data cannot be null or empty.", nameof(data));
            if ( key == null || key.Length != KeySize )
                throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));

            byte[] nonce = new byte[NonceSize];
            RandomNumberGenerator.Fill(nonce);

            // Generate ChaCha20 keystream
            byte[] keyStream = GenerateKeyStream(key, nonce, data.Length);
            byte[] ciphertext = new byte[data.Length];

            // Encrypt data with keystream
            for ( int i = 0; i < data.Length; i++ )
                ciphertext[i] = (byte) (data[i] ^ keyStream[i]);

            // Generate Poly1305 key and compute MAC
            byte[] poly1305Key = GenerateKeyStream(key, nonce, KeySize);
            byte[] tag = ComputePoly1305(poly1305Key, ciphertext);

            // Combine nonce, ciphertext, and tag
            byte[] result = new byte[NonceSize + ciphertext.Length + TagSize];

            Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
            Buffer.BlockCopy(ciphertext, 0, result, NonceSize, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, NonceSize + ciphertext.Length, TagSize);

            return result;
        }

        public override byte[] Decrypt(byte[] encryptedData, byte[] key)
        {
            if ( encryptedData == null || encryptedData.Length < NonceSize + TagSize )
                throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));

            // Extract nonce, ciphertext and tag
            byte[] nonce = new byte[NonceSize];
            Buffer.BlockCopy(encryptedData, 0, nonce, 0, NonceSize);

            int ciphertextLength = encryptedData.Length - NonceSize - TagSize;
            byte[] ciphertext = new byte[ciphertextLength];
            Buffer.BlockCopy(encryptedData, NonceSize, ciphertext, 0, ciphertextLength);

            byte[] tag = new byte[TagSize];
            Buffer.BlockCopy(encryptedData, NonceSize + ciphertextLength, tag, 0, TagSize);

            // Verify MAC
            byte[] poly1305Key = GenerateKeyStream(key, nonce, KeySize);
            byte[] computedTag = ComputePoly1305(poly1305Key, ciphertext);
            if ( !ConstantTimeEquals(tag, computedTag) )
                throw new CryptographicException("Authentication failed.");

            // Decrypt data
            byte[] keyStream = GenerateKeyStream(key, nonce, ciphertextLength);
            byte[] plaintext = new byte[ciphertextLength];
            for ( int i = 0; i < ciphertextLength; i++ )
                plaintext[i] = (byte) (ciphertext[i] ^ keyStream[i]);

            return plaintext;
        }

        private byte[] GenerateKeyStream(byte[] key, byte[] nonce, int length)
        {
            byte[] keyStream = new byte[length];
            Span<uint> state = stackalloc uint[16];
            uint counter = 0;

            // Initialize state constants (can be made static readonly)
            state[0] = 0x61707865;
            state[1] = 0x3320646E;
            state[2] = 0x79622D32;
            state[3] = 0x6B206574;

            // Set key using massaged data
            var keyUints = EndianHelper.MassageToUInt32Array(key, 0, key.Length);
            keyUints.AsSpan().CopyTo(state.Slice(4, 8));

            // Set counter and nonce
            state[12] = 0; // counter starts at 0
            var nonceUints = EndianHelper.MassageToUInt32Array(nonce, 0, nonce.Length);
            nonceUints.AsSpan().CopyTo(state.Slice(13, 3));

            Span<uint> working = stackalloc uint[16];
            Span<byte> block = stackalloc byte[BlockSize];

            int position = 0;
            while ( position < length )
            {
                state.CopyTo(working);
                ChaCha20Block(working);

                // Write block with proper endianness
                for ( int i = 0; i < 16; i++ )
                {
                    uint sum = working[i] + state[i];
                    EndianHelper.WriteUInt32ToBytes(sum, block.Slice(i * 4, 4));
                }

                int bytesToCopy = Math.Min(BlockSize, length - position);
                block.Slice(0, bytesToCopy).CopyTo(keyStream.AsSpan(position));
                position += bytesToCopy;
                state[12]++;
            }

            return keyStream;
        }

        private void ChaCha20Block(Span<uint> state)
        {
            for ( int i = 0; i < 10; i++ )
            {
                // Column rounds
                QuarterRound(ref state[0], ref state[4], ref state[8], ref state[12]);
                QuarterRound(ref state[1], ref state[5], ref state[9], ref state[13]);
                QuarterRound(ref state[2], ref state[6], ref state[10], ref state[14]);
                QuarterRound(ref state[3], ref state[7], ref state[11], ref state[15]);

                // Diagonal rounds
                QuarterRound(ref state[0], ref state[5], ref state[10], ref state[15]);
                QuarterRound(ref state[1], ref state[6], ref state[11], ref state[12]);
                QuarterRound(ref state[2], ref state[7], ref state[8], ref state[13]);
                QuarterRound(ref state[3], ref state[4], ref state[9], ref state[14]);
            }
        }

        private void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b; d ^= a; d = RotateLeft(d, 16);
            c += d; b ^= c; b = RotateLeft(b, 12);
            a += b; d ^= a; d = RotateLeft(d, 8);
            c += d; b ^= c; b = RotateLeft(b, 7);
        }

        private static uint RotateLeft(uint value, int offset)
            => (value << offset) | (value >> (32 - offset));

        private byte[] ComputePoly1305(byte[] key, byte[] message)
        {
            if ( key.Length != KeySize )
                throw new ArgumentException("Poly1305 key must be 32 bytes.");

            // Initialize r and s with massaged data
            Span<byte> r = stackalloc byte[16];
            Span<byte> s = stackalloc byte[16];
            key.AsSpan(0, 16).CopyTo(r);
            key.AsSpan(16, 16).CopyTo(s);

            // Clamp r
            r[3] &= 15;
            r[7] &= 15;
            r[11] &= 15;
            r[15] &= 15;
            r[4] &= 252;
            r[8] &= 252;
            r[12] &= 252;

            // Convert to uint arrays using massager
            var rNum = EndianHelper.MassageToUInt32Array(r, 0, 16);
            var sNum = EndianHelper.MassageToUInt32Array(s, 0, 16);

            for ( int i = 0; i < 4; i++ )
            {
                rNum[i] = (uint) (r[i * 4] | (r[i * 4 + 1] << 8) | (r[i * 4 + 2] << 16) | (r[i * 4 + 3] << 24));
                sNum[i] = (uint) (s[i * 4] | (s[i * 4 + 1] << 8) | (s[i * 4 + 2] << 16) | (s[i * 4 + 3] << 24));
            }

            // Initialize accumulator
            ulong h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

            // Process message blocks
            int blockSize = 16;
            int blocksCount = (message.Length + blockSize - 1) / blockSize;

            for ( int i = 0; i < blocksCount; i++ )
            {
                int blockLen = Math.Min(blockSize, message.Length - i * blockSize);
                uint[] block = new uint[4];

                if ( blockLen == 16 )
                {
                    for ( int j = 0; j < 4; j++ )
                    {
                        int index = i * 16 + j * 4;
                        block[j] = (uint) (message[index] |
                                        (message[index + 1] << 8) |
                                        (message[index + 2] << 16) |
                                        (message[index + 3] << 24));
                    }
                }
                else
                {
                    byte[] padding = new byte[16];
                    Buffer.BlockCopy(message, i * 16, padding, 0, blockLen);
                    padding[blockLen] = 1;

                    for ( int j = 0; j < 4; j++ )
                    {
                        block[j] = (uint) (padding[j * 4] |
                                        (padding[j * 4 + 1] << 8) |
                                        (padding[j * 4 + 2] << 16) |
                                        (padding[j * 4 + 3] << 24));
                    }
                }

                // Add block to accumulator
                ulong t0 = h0 + block[0];
                ulong t1 = h1 + block[1];
                ulong t2 = h2 + block[2];
                ulong t3 = h3 + block[3];

                h0 = (uint) t0; h1 = (uint) t1; h2 = (uint) t2; h3 = (uint) t3;
                h4 += (uint) (t0 >> 32 | t1 >> 32 | t2 >> 32 | t3 >> 32);

                // Multiply by r
                ulong d0 = h0 * rNum[0] + h1 * rNum[3] + h2 * rNum[2] + h3 * rNum[1];
                ulong d1 = h0 * rNum[1] + h1 * rNum[0] + h2 * rNum[3] + h3 * rNum[2];
                ulong d2 = h0 * rNum[2] + h1 * rNum[1] + h2 * rNum[0] + h3 * rNum[3];
                ulong d3 = h0 * rNum[3] + h1 * rNum[2] + h2 * rNum[1] + h3 * rNum[0];

                // Partial reduction mod 2^130 - 5
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
                h4 = h4 * rNum[0] + (uint) c;

                c = h4 >> 2;
                h4 &= 3;
                h0 += c * 5;
                h1 += h0 >> 32;
                h0 &= 0xffffffff;
            }

            // Final reduction and addition of s
            ulong f0 = h0 + sNum[0];
            ulong f1 = h1 + sNum[1] + (f0 >> 32);
            ulong f2 = h2 + sNum[2] + (f1 >> 32);
            ulong f3 = h3 + sNum[3] + (f2 >> 32);

            h0 = (uint) f0; h1 = (uint) f1;
            h2 = (uint) f2; h3 = (uint) f3;

            byte[] tag = new byte[16];
            EndianHelper.WriteUInt64ToBytes(h0, tag.AsSpan(0, 4));
            EndianHelper.WriteUInt64ToBytes(h1, tag.AsSpan(4, 4));
            EndianHelper.WriteUInt64ToBytes(h2, tag.AsSpan(8, 4));
            EndianHelper.WriteUInt64ToBytes(h3, tag.AsSpan(12, 4));

            return tag;
        }
        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if ( a.Length != b.Length )
                return false;

            uint diff = 0;
            for ( int i = 0; i < a.Length; i++ )
                diff |= (uint) (a[i] ^ b[i]);
            return diff == 0;
        }
        public override byte[] GenerateKey()
        {
            byte[] key = new byte[KeySize];
            RandomNumberGenerator.Fill(key);
            return key;
        }
    }
}
