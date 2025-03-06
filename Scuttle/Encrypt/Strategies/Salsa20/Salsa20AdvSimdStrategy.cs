using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Versioning;
using Scuttle.Encrypt.BernsteinCore;

namespace Scuttle.Encrypt.Strategies.Salsa20
{
    /// <summary>
    /// ARM NEON optimized implementation of Salsa20
    /// </summary>
    [SupportedOSPlatform("linux-arm64")]
    [SupportedOSPlatform("macos-arm64")]
    [SupportedOSPlatform("windows-arm64")]
    internal class Salsa20AdvSimdStrategy : BaseSalsa20Strategy
    {
        public override int Priority => 200; // Same priority as SSE2
        public override string Description => "ARM NEON Implementation";

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

                    // Load state into ARM NEON registers
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
                        SalsaQuarterRoundAdvSimd(ref working[0], ref working[1], ref working[2], ref working[3]);
                        SalsaQuarterRoundAdvSimd(ref working[1], ref working[2], ref working[3], ref working[0]);
                    }

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
                    int bytesToProcess = Math.Min(64, inputChunk.Length - position);
                    VectorOperations.ApplyXorAdvSimd(
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
        private static void SalsaQuarterRoundAdvSimd(
            ref Vector128<uint> a, ref Vector128<uint> b,
            ref Vector128<uint> c, ref Vector128<uint> d)
        {
            // Implementation using ARM NEON intrinsics
            var temp = AdvSimd.Add(a.AsUInt32(), d.AsUInt32());

            // Rotate left by 7
            temp = AdvSimd.Xor(
                AdvSimd.ShiftLeftLogical(temp, 7),
                AdvSimd.ShiftRightLogical(temp, 32 - 7));

            b = AdvSimd.Xor(b.AsUInt32(), temp.AsUInt32()).AsUInt32();

            temp = AdvSimd.Add(b.AsUInt32(), a.AsUInt32());

            // Rotate left by 9
            temp = AdvSimd.Xor(
                AdvSimd.ShiftLeftLogical(temp, 9),
                AdvSimd.ShiftRightLogical(temp, 32 - 9));

            c = AdvSimd.Xor(c.AsUInt32(), temp.AsUInt32()).AsUInt32();

            temp = AdvSimd.Add(c.AsUInt32(), b.AsUInt32());

            // Rotate left by 13
            temp = AdvSimd.Xor(
                AdvSimd.ShiftLeftLogical(temp, 13),
                AdvSimd.ShiftRightLogical(temp, 32 - 13));

            d = AdvSimd.Xor(d.AsUInt32(), temp.AsUInt32()).AsUInt32();

            temp = AdvSimd.Add(d.AsUInt32(), c.AsUInt32());

            // Rotate left by 18
            temp = AdvSimd.Xor(
                AdvSimd.ShiftLeftLogical(temp, 18),
                AdvSimd.ShiftRightLogical(temp, 32 - 18));

            a = AdvSimd.Xor(a.AsUInt32(), temp.AsUInt32()).AsUInt32();
        }

        public static bool IsSupported => AdvSimd.IsSupported;
    }
}
