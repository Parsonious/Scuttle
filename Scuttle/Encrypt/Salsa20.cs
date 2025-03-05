using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Numerics;
using Scuttle.Base;
using Scuttle.Helpers;
using Scuttle.Interfaces;

internal class Salsa20Encrypt : BaseEncryption
{
    private const int KEY_SIZE = 32;    // 256 bits
    private const int NONCE_SIZE = 8;   // 64 bits
    private const int STATE_SIZE = 16;  // 16 32-bit words

    public Salsa20Encrypt(IEncoder encoder) : base(encoder)
    {
    }   

    public override byte[] Encrypt(byte[] data, byte[] key)
    {
        if ( data == null || data.Length == 0 )
            throw new ArgumentException("Data cannot be null or empty.", nameof(data));

        if ( key == null || key.Length != KEY_SIZE )
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes.", nameof(key));

        byte[] nonce = new byte[NONCE_SIZE];
        RandomNumberGenerator.Fill(nonce);

        // Combine nonce and encrypted data
        byte[] result = new byte[NONCE_SIZE + data.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, NONCE_SIZE);

        // Generate keystream and XOR with data
        byte[] keystream = GenerateKeystream(key, nonce, data.Length);
        for ( int i = 0; i < data.Length; i++ )
        {
            result[NONCE_SIZE + i] = (byte) (data[i] ^ keystream[i]);
        }

        return result;
    }

    public override byte[] Decrypt(byte[] encryptedData, byte[] key)
    {
        if ( encryptedData == null || encryptedData.Length < NONCE_SIZE )
            throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));

        if ( key == null || key.Length != KEY_SIZE )
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes.", nameof(key));

        // Extract nonce
        byte[] nonce = new byte[NONCE_SIZE];
        Buffer.BlockCopy(encryptedData, 0, nonce, 0, NONCE_SIZE);

        int dataLength = encryptedData.Length - NONCE_SIZE;
        byte[] result = new byte[dataLength];
        Buffer.BlockCopy(encryptedData, NONCE_SIZE, result, 0, dataLength);

        // Generate keystream and XOR with encrypted data
        byte[] keystream = GenerateKeystream(key, nonce, dataLength);
        for ( int i = 0; i < dataLength; i++ )
        {
            result[i] = (byte) (result[i] ^ keystream[i]);
        }

        return result;
    }

    private byte[] GenerateKeystream(byte[] key, byte[] nonce, int length)
    {
        // Use direct allocation for the output since it's the return value
        byte[] output = new byte[length];
        const int BLOCK_SIZE = 64;

        // Stack allocation for temporary working space
        Span<uint> state = stackalloc uint[STATE_SIZE];
        Span<uint> working = stackalloc uint[STATE_SIZE];
        Span<byte> block = stackalloc byte[BLOCK_SIZE];

        int position = 0;

        // Initialize state with SIMD acceleration if available
        CryptoEndianness.InitializeChaChaState(state, key, nonce, 0, true);

        // Process blocks in chunks for better cache utilization
        while ( position < length )
        {
            state.CopyTo(working);

            // Unroll quarter round operations for better instruction pipelining
            for ( int round = 0; round < 10; round++ )
            {
                // Column rounds (vectorized if available)
                QuarterRoundFast(ref working[0], ref working[4], ref working[8], ref working[12]);
                QuarterRoundFast(ref working[5], ref working[9], ref working[13], ref working[1]);
                QuarterRoundFast(ref working[10], ref working[14], ref working[2], ref working[6]);
                QuarterRoundFast(ref working[15], ref working[3], ref working[7], ref working[11]);

                // Row rounds (vectorized if available)
                QuarterRoundFast(ref working[0], ref working[1], ref working[2], ref working[3]);
                QuarterRoundFast(ref working[5], ref working[6], ref working[7], ref working[4]);
                QuarterRoundFast(ref working[10], ref working[11], ref working[8], ref working[9]);
                QuarterRoundFast(ref working[15], ref working[12], ref working[13], ref working[14]);
            }

            // Add original state with SIMD when available
            for ( int i = 0; i < STATE_SIZE; i++ )
            {
                working[i] += state[i];
            }

            // Optimize endianness conversion
            CryptoEndianness.ProcessBlock32(block, working);

            int bytesToCopy = Math.Min(BLOCK_SIZE, length - position);
            block.Slice(0, bytesToCopy).CopyTo(output.AsSpan(position));
            position += bytesToCopy;

            // Increment counter with carry handling
            if ( ++state[8] == 0 ) state[9]++;
        }

        return output;
    }

    // Optimized quarter round implementation
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRoundFast(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        b ^= BitOperations.RotateLeft((a + d), 7);
        c ^= BitOperations.RotateLeft((b + a), 9);
        d ^= BitOperations.RotateLeft((c + b), 13);
        a ^= BitOperations.RotateLeft((d + c), 18);
    }
    private static uint RotateLeft(uint value, int offset)
        => (value << offset) | (value >> (32 - offset));

    public override byte[] GenerateKey()
    {
        byte[] key = new byte[KEY_SIZE];
        RandomNumberGenerator.Fill(key);
        return key;
    }
}
