using System.Buffers;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Versioning;
using Scuttle.Encrypt.BernsteinCore;
using Scuttle.Encrypt.BernSteinCore;

namespace Scuttle.Encrypt.Strategies.XChaCha20
{
    /// <summary>
    /// SSE2-optimized implementation of XChaCha20
    /// </summary>
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    internal class XChaCha20Sse2Strategy : BaseXChaCha20Strategy
    {
        public override int Priority => 200;
        public override string Description => "SSE2 SIMD Implementation";

        protected override void ProcessChunk(ReadOnlySpan<byte> inputChunk, byte[] key, ReadOnlySpan<byte> nonce, Span<byte> outputChunk)
        {
            int position = 0;
            uint counter = 0;
            byte[] blockBytes = ArrayPool<byte>.Shared.Rent(ChaChaBlockSize);

            try
            {
                // Initialize state
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

                // Set nonce
                initialState[13] = BitConverter.ToUInt32(nonce.Slice(0, 4));
                initialState[14] = BitConverter.ToUInt32(nonce.Slice(4, 4));
                initialState[15] = 0; // Last word is zero for XChaCha20

                while ( position < inputChunk.Length )
                {
                    // Set counter for this block
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

                    // Apply ChaCha20 rounds
                    for ( int i = 0; i < 10; i++ )
                    {
                        ChaChaUtils.ChaChaRoundSse2(ref working[0], ref working[1], ref working[2], ref working[3]);
                    }

                    // Add original state
                    working[0] = Sse2.Add(working[0], state[0]);
                    working[1] = Sse2.Add(working[1], state[1]);
                    working[2] = Sse2.Add(working[2], state[2]);
                    working[3] = Sse2.Add(working[3], state[3]);

                    // Store to temporary buffer
                    VectorOperations.StoreVector128(working[0], blockBytes.AsSpan(0));
                    VectorOperations.StoreVector128(working[1], blockBytes.AsSpan(16));
                    VectorOperations.StoreVector128(working[2], blockBytes.AsSpan(32));
                    VectorOperations.StoreVector128(working[3], blockBytes.AsSpan(48));

                    // XOR with input to produce output
                    int bytesToProcess = Math.Min(ChaChaBlockSize, inputChunk.Length - position);
                    VectorOperations.ApplyXorSse2(
                        inputChunk.Slice(position, bytesToProcess),
                        blockBytes.AsSpan(0, bytesToProcess),
                        outputChunk.Slice(position, bytesToProcess));

                    position += bytesToProcess;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(blockBytes);
            }
        }

        protected override void GenerateKeyStreamInternal(Span<uint> initialState, Span<byte> keyStream)
        {
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

        public static bool IsSupported => Sse2.IsSupported;
    }
}
