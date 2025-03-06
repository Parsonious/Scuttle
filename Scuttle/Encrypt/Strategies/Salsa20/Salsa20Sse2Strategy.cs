// File: Scuttle/Encrypt/Strategies/Salsa20/Salsa20Sse2Strategy.cs
using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Versioning;
using Scuttle.Encrypt.BernsteinCore;

namespace Scuttle.Encrypt.Strategies.Salsa20
{
    /// <summary>
    /// SSE2-optimized implementation of Salsa20
    /// </summary>
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    internal class Salsa20Sse2Strategy : BaseSalsa20Strategy
    {
        public override int Priority => 200;
        public override string Description => "SSE2 SIMD Implementation";

        protected override void ProcessChunk(ReadOnlySpan<byte> inputChunk, Span<uint> initialState, Span<byte> outputChunk)
        {
            int position = 0;
            uint counter = initialState[8]; // Use the counter from the state
            byte[] blockBytes = ArrayPool<byte>.Shared.Rent(64); // BlockSize

            try
            {
                Span<uint> blockState = stackalloc uint[16];

                while ( position < inputChunk.Length )
                {
                    // Make a copy of the state for this block
                    initialState.CopyTo(blockState);

                    // Set the counter for this block
                    blockState[8] = counter++;
                    if ( counter == 0 ) blockState[9]++; // Handle overflow

                    // Load state into SSE2 registers
                    Vector128<uint>[] state =
                    [
                        Vector128.Create(blockState[0], blockState[1], blockState[2], blockState[3]),
                        Vector128.Create(blockState[4], blockState[5], blockState[6], blockState[7]),
                        Vector128.Create(blockState[8], blockState[9], blockState[10], blockState[11]),
                        Vector128.Create(blockState[12], blockState[13], blockState[14], blockState[15]),
                    ];

                    // Create working copy
                    Vector128<uint>[] working = new Vector128<uint>[4];
                    state.CopyTo(working, 0);

                    // Apply Salsa20 rounds
                    for ( int i = 0; i < 10; i++ )
                    {
                        SalsaQuarterRoundSse2(ref working[0], ref working[1], ref working[2], ref working[3]);
                        SalsaQuarterRoundSse2(ref working[1], ref working[2], ref working[3], ref working[0]);
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
                    int bytesToProcess = Math.Min(64, inputChunk.Length - position);
                    VectorOperations.ApplyXorSse2(
                        inputChunk.Slice(position, bytesToProcess),
                        blockBytes.AsSpan(0, bytesToProcess),
                        outputChunk.Slice(position, bytesToProcess));

                    position += bytesToProcess;
                }

                // Update the counter in the original state
                initialState[8] = counter;
                if ( counter == 0 ) initialState[9]++;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(blockBytes);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void SalsaQuarterRoundSse2(ref Vector128<uint> a, ref Vector128<uint> b,
            ref Vector128<uint> c, ref Vector128<uint> d)
        {
            // Implementation using SSE2 intrinsics
            var temp = Sse2.Add(a, d);
            temp = Sse2.Or(Sse2.ShiftLeftLogical(temp, 7), Sse2.ShiftRightLogical(temp, 32 - 7));
            b = Sse2.Xor(b, temp);

            temp = Sse2.Add(b, a);
            temp = Sse2.Or(Sse2.ShiftLeftLogical(temp, 9), Sse2.ShiftRightLogical(temp, 32 - 9));
            c = Sse2.Xor(c, temp);

            temp = Sse2.Add(c, b);
            temp = Sse2.Or(Sse2.ShiftLeftLogical(temp, 13), Sse2.ShiftRightLogical(temp, 32 - 13));
            d = Sse2.Xor(d, temp);

            temp = Sse2.Add(d, c);
            temp = Sse2.Or(Sse2.ShiftLeftLogical(temp, 18), Sse2.ShiftRightLogical(temp, 32 - 18));
            a = Sse2.Xor(a, temp);
        }

        public static bool IsSupported => Sse2.IsSupported;
    }
}
