using System.Security.Cryptography;
using System.Text;
using Token_Generator.Base;
using Token_Generator.Interfaces;

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
        uint[] state = new uint[STATE_SIZE];
        byte[] output = new byte[length];
        int position = 0;

        // Initialize state with constants
        state[0] = 0x61707865; // "expa"
        state[5] = 0x3320646e; // "nd 3"
        state[10] = 0x79622d32; // "2-by"
        state[15] = 0x6b206574; // "te k"

        // Set key (8 words)
        for ( int i = 0; i < 8; i++ )
        {
            state[i + 1] = BitConverter.ToUInt32(key, i * 4);
        }

        // Set nonce (2 words)
        state[6] = BitConverter.ToUInt32(nonce, 0);
        state[7] = BitConverter.ToUInt32(nonce, 4);

        while ( position < length )
        {
            uint[] working = (uint[]) state.Clone();

            // Perform 20 rounds (10 double rounds)
            for ( int round = 0; round < 10; round++ )
            {
                // Column rounds
                QuarterRound(ref working[0], ref working[4], ref working[8], ref working[12]);
                QuarterRound(ref working[5], ref working[9], ref working[13], ref working[1]);
                QuarterRound(ref working[10], ref working[14], ref working[2], ref working[6]);
                QuarterRound(ref working[15], ref working[3], ref working[7], ref working[11]);

                // Row rounds
                QuarterRound(ref working[0], ref working[1], ref working[2], ref working[3]);
                QuarterRound(ref working[5], ref working[6], ref working[7], ref working[4]);
                QuarterRound(ref working[10], ref working[11], ref working[8], ref working[9]);
                QuarterRound(ref working[15], ref working[12], ref working[13], ref working[14]);
            }

            // Add original state to working state
            for ( int i = 0; i < STATE_SIZE; i++ )
            {
                working[i] += state[i];
            }

            // Convert state to bytes and copy to output
            byte[] block = new byte[64];
            for ( int i = 0; i < STATE_SIZE; i++ )
            {
                BitConverter.GetBytes(working[i]).CopyTo(block, i * 4);
            }

            int blockSize = Math.Min(64, length - position);
            Buffer.BlockCopy(block, 0, output, position, blockSize);
            position += blockSize;

            // Increment counter
            state[8]++;
            if ( state[8] == 0 ) state[9]++;
        }

        return output;
    }

    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        b ^= RotateLeft((a + d), 7);
        c ^= RotateLeft((b + a), 9);
        d ^= RotateLeft((c + b), 13);
        a ^= RotateLeft((d + c), 18);
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
