using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Versioning;
using Scuttle.Encrypt.BernsteinCore;
using Scuttle.Encrypt.BernSteinCore;
using Scuttle.Helpers;

namespace Scuttle.Encrypt.Strategies.XChaCha20
{
    /// <summary>
    /// ARM NEON optimized implementation of XChaCha20
    /// </summary>
    // Fix the platform attribute errors by using correct platform names
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    [SupportedOSPlatform("windows")]
    internal class XChaCha20AdvSimdStrategy : BaseXChaCha20Strategy
    {
        public override int Priority => 200; // Same priority as SSE2
        public override string Description => "ARM NEON Implementation";

        protected override void ProcessChunk(ReadOnlySpan<byte> inputChunk, byte[] key, ReadOnlySpan<byte> nonce, Span<byte> outputChunk)
        {
            // Existing code remains the same...
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

                    // Load state into ARM NEON registers
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
                        // Fix: Use the correct method name from ChaChaUtils
                        ChaChaUtils.ChaChaRoundAdvSimd(ref working[0], ref working[1], ref working[2], ref working[3]);
                    }

                    // Rest of the method remains the same...
                    // Add original state
                    working[0] = AdvSimd.Add(working[0].AsUInt32(), state[0].AsUInt32()).AsUInt32();
                    working[1] = AdvSimd.Add(working[1].AsUInt32(), state[1].AsUInt32()).AsUInt32();
                    working[2] = AdvSimd.Add(working[2].AsUInt32(), state[2].AsUInt32()).AsUInt32();
                    working[3] = AdvSimd.Add(working[3].AsUInt32(), state[3].AsUInt32()).AsUInt32();

                    // Store to temporary buffer
                    VectorOperations.StoreVector128AdvSimd(working[0], blockBytes.AsSpan(0));
                    VectorOperations.StoreVector128AdvSimd(working[1], blockBytes.AsSpan(16));
                    VectorOperations.StoreVector128AdvSimd(working[2], blockBytes.AsSpan(32));
                    VectorOperations.StoreVector128AdvSimd(working[3], blockBytes.AsSpan(48));

                    // XOR with input to produce output
                    int bytesToProcess = Math.Min(ChaChaBlockSize, inputChunk.Length - position);
                    VectorOperations.ApplyXorAdvSimd(
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
            // Rest of the method remains the same...
            int position = 0;
            uint counter = 0;

            while ( position < keyStream.Length )
            {
                // Update counter for this block
                initialState[12] = counter++;

                // Load state into ARM NEON registers
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
                    // Fix: Use the correct method name from ChaChaUtils
                    ChaChaUtils.ChaChaRoundAdvSimd(ref working[0], ref working[1], ref working[2], ref working[3]);
                }

                // Rest of method remains the same...
                working[0] = AdvSimd.Add(working[0].AsUInt32(), state[0].AsUInt32()).AsUInt32();
                working[1] = AdvSimd.Add(working[1].AsUInt32(), state[1].AsUInt32()).AsUInt32();
                working[2] = AdvSimd.Add(working[2].AsUInt32(), state[2].AsUInt32()).AsUInt32();
                working[3] = AdvSimd.Add(working[3].AsUInt32(), state[3].AsUInt32()).AsUInt32();

                byte[] blockBytes = ArrayPool<byte>.Shared.Rent(ChaChaBlockSize);

                try
                {
                    VectorOperations.StoreVector128AdvSimd(working[0], blockBytes.AsSpan(0));
                    VectorOperations.StoreVector128AdvSimd(working[1], blockBytes.AsSpan(16));
                    VectorOperations.StoreVector128AdvSimd(working[2], blockBytes.AsSpan(32));
                    VectorOperations.StoreVector128AdvSimd(working[3], blockBytes.AsSpan(48));

                    int bytesToCopy = Math.Min(ChaChaBlockSize, keyStream.Length - position);
                    blockBytes.AsSpan(0, bytesToCopy).CopyTo(keyStream.Slice(position, bytesToCopy));
                    position += bytesToCopy;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(blockBytes);
                }
            }
        }

        /// <summary>
        /// Optimized implementation of HChaCha20 using ARM NEON
        /// </summary>
        public override byte[] HChaCha20(byte[] key, ReadOnlySpan<byte> nonce)
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

            // Create working copy for SIMD operations
            Vector128<uint>[] v = new Vector128<uint>[4];
            v[0] = Vector128.Create(state[0], state[1], state[2], state[3]);
            v[1] = Vector128.Create(state[4], state[5], state[6], state[7]);
            v[2] = Vector128.Create(state[8], state[9], state[10], state[11]);
            v[3] = Vector128.Create(state[12], state[13], state[14], state[15]);

            // Apply the ChaCha rounds
            for ( int i = 0; i < 10; i++ )
            {
                // Column rounds
                ChaChaUtils.ChaChaRoundAdvSimd(ref v[0], ref v[1], ref v[2], ref v[3]);

                // Diagonal rounds - We need to rearrange the vectors
                // This is a simplified approach - in practice, we might use specific shuffles
                Span<uint> temp = stackalloc uint[16];
                StoreVectorsToSpan(v, temp);

                // Rearrange for diagonal round
                Span<uint> diag = stackalloc uint[16];
                diag[0] = temp[0]; diag[1] = temp[5]; diag[2] = temp[10]; diag[3] = temp[15];
                diag[4] = temp[4]; diag[5] = temp[9]; diag[6] = temp[14]; diag[7] = temp[3];
                diag[8] = temp[8]; diag[9] = temp[13]; diag[10] = temp[2]; diag[11] = temp[7];
                diag[12] = temp[12]; diag[13] = temp[1]; diag[14] = temp[6]; diag[15] = temp[11];

                // Load diagonals back into vectors
                Vector128<uint>[] d = new Vector128<uint>[4];
                d[0] = Vector128.Create(diag[0], diag[1], diag[2], diag[3]);
                d[1] = Vector128.Create(diag[4], diag[5], diag[6], diag[7]);
                d[2] = Vector128.Create(diag[8], diag[9], diag[10], diag[11]);
                d[3] = Vector128.Create(diag[12], diag[13], diag[14], diag[15]);

                // Apply quarter round
                ChaChaUtils.ChaChaRoundAdvSimd(ref d[0], ref d[1], ref d[2], ref d[3]);

                // Restore original order
                StoreVectorsToSpan(d, diag);

                temp[0] = diag[0]; temp[5] = diag[1]; temp[10] = diag[2]; temp[15] = diag[3];
                temp[4] = diag[4]; temp[9] = diag[5]; temp[14] = diag[6]; temp[3] = diag[7];
                temp[8] = diag[8]; temp[13] = diag[9]; temp[2] = diag[10]; temp[7] = diag[11];
                temp[12] = diag[12]; temp[1] = diag[13]; temp[6] = diag[14]; temp[11] = diag[15];

                // Load back into vectors
                v[0] = Vector128.Create(temp[0], temp[1], temp[2], temp[3]);
                v[1] = Vector128.Create(temp[4], temp[5], temp[6], temp[7]);
                v[2] = Vector128.Create(temp[8], temp[9], temp[10], temp[11]);
                v[3] = Vector128.Create(temp[12], temp[13], temp[14], temp[15]);
            }

            // Extract subkey (first 4 words and last 4 words of the state)
            byte[] subkey = new byte[32];

            // Store vectors temporarily
            StoreVectorsToSpan(v, state);

            // Extract first 4 words (state[0-3]) and last 4 words (state[12-15])
            for ( int i = 0; i < 4; i++ )
            {
                EndianHelper.WriteUInt32ToBytes(state[i], subkey, i * 4);
                EndianHelper.WriteUInt32ToBytes(state[12 + i], subkey, 16 + i * 4);
            }

            return subkey;
        }

        // Helper method to store Vector128<uint> array to uint span
        private static void StoreVectorsToSpan(Vector128<uint>[] vectors, Span<uint> output)
        {
            for ( int i = 0; i < 4; i++ )
            {
                for ( int j = 0; j < 4; j++ )
                {
                    output[i * 4 + j] = vectors[i].GetElement(j);
                }
            }
        }

        public static bool IsSupported => AdvSimd.IsSupported;
    }
}
