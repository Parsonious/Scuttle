using System.Security.Cryptography;
using System.Text;
using Token_Generator.Encoders;
using Token_Generator.Interfaces;

internal class ThreefishEncrypt : IEncryption
{
    private const int KEY_SIZE = 64;    // 512 bits
    private const int TWEAK_SIZE = 16;  // 128 bits
    private const int BLOCK_SIZE = 64;  // 512 bits
    private const ulong CONST_240 = 0x1BD11BDAA9FC1A22;

    private static readonly int[] ROTATION_0_0 = { 46, 36, 19, 37 };
    private static readonly int[] ROTATION_1_0 = { 33, 27, 14, 42 };
    private static readonly int[] ROTATION_2_0 = { 17, 49, 36, 39 };
    private static readonly int[] ROTATION_3_0 = { 44, 39, 56, 34 };

    private static readonly int[] PERMUTATION = { 0, 3, 2, 1 };

    public string EncryptAndEncode(string data, byte[] key)
    {
        byte[] dataBytes = Encoding.UTF8.GetBytes(data);
        byte[] encrypted = Encrypt(dataBytes, key);
        return Convert.ToBase64String(encrypted);
    }

    public string DecodeAndDecrypt(string encodedData, byte[] key)
    {
        byte[] encryptedBytes = Convert.FromBase64String(encodedData);
        byte[] decrypted = Decrypt(encryptedBytes, key);
        return Encoding.UTF8.GetString(decrypted);
    }
    public byte[] GenerateKey()
    {
        byte[] key = new byte[KEY_SIZE];
        RandomNumberGenerator.Fill(key);
        return key;
    }
    public byte[] Encrypt(byte[] data, byte[] key)
    {
        if ( data == null || data.Length == 0 )
            throw new ArgumentException("Data cannot be null or empty.", nameof(data));

        if ( key == null || key.Length != KEY_SIZE )
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes.", nameof(key));

        // Generate random tweak
        byte[] tweak = new byte[TWEAK_SIZE];
        RandomNumberGenerator.Fill(tweak);

        // Pad data using PKCS7
        int paddingLength = BLOCK_SIZE - (data.Length % BLOCK_SIZE);
        byte[] paddedData = new byte[data.Length + paddingLength];
        Buffer.BlockCopy(data, 0, paddedData, 0, data.Length);
        for ( int i = data.Length; i < paddedData.Length; i++ )
        {
            paddedData[i] = (byte) paddingLength;
        }

        // Process each block
        byte[] ciphertext = new byte[paddedData.Length];
        ulong[] keySchedule = GenerateKeySchedule(key, tweak);

        for ( int i = 0; i < paddedData.Length; i += BLOCK_SIZE )
        {
            byte[] block = new byte[BLOCK_SIZE];
            Buffer.BlockCopy(paddedData, i, block, 0, BLOCK_SIZE);
            byte[] encryptedBlock = EncryptBlock(block, keySchedule);
            Buffer.BlockCopy(encryptedBlock, 0, ciphertext, i, BLOCK_SIZE);
        }

        // Combine tweak, original length, and ciphertext
        byte[] result = new byte[TWEAK_SIZE + 4 + ciphertext.Length];
        Buffer.BlockCopy(tweak, 0, result, 0, TWEAK_SIZE);
        Buffer.BlockCopy(BitConverter.GetBytes(data.Length), 0, result, TWEAK_SIZE, 4);
        Buffer.BlockCopy(ciphertext, 0, result, TWEAK_SIZE + 4, ciphertext.Length);

        return result;
    }

    public byte[] Decrypt(byte[] encryptedData, byte[] key)
    {
        if ( encryptedData == null || encryptedData.Length < TWEAK_SIZE + 4 )
            throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));

        // Extract tweak and original length
        byte[] tweak = new byte[TWEAK_SIZE];
        Buffer.BlockCopy(encryptedData, 0, tweak, 0, TWEAK_SIZE);
        int originalLength = BitConverter.ToInt32(encryptedData, TWEAK_SIZE);

        // Generate key schedule
        ulong[] keySchedule = GenerateKeySchedule(key, tweak);

        // Decrypt data
        byte[] ciphertext = new byte[encryptedData.Length - TWEAK_SIZE - 4];
        Buffer.BlockCopy(encryptedData, TWEAK_SIZE + 4, ciphertext, 0, ciphertext.Length);

        byte[] decrypted = new byte[ciphertext.Length];
        for ( int i = 0; i < ciphertext.Length; i += BLOCK_SIZE )
        {
            byte[] block = new byte[BLOCK_SIZE];
            Buffer.BlockCopy(ciphertext, i, block, 0, BLOCK_SIZE);
            byte[] decryptedBlock = DecryptBlock(block, keySchedule);
            Buffer.BlockCopy(decryptedBlock, 0, decrypted, i, BLOCK_SIZE);
        }

        // Remove padding and trim to original length
        int paddingLength = decrypted[^1];
        byte[] result = new byte[originalLength];
        Buffer.BlockCopy(decrypted, 0, result, 0, originalLength);

        return result;
    }

    private byte[] EncryptBlock(byte[] block, ulong[] keySchedule)
    {
        ulong[] state = new ulong[8];
        for ( int i = 0; i < 8; i++ )
        {
            state[i] = BitConverter.ToUInt64(block, i * 8);
        }

        // Apply 72 rounds of mixing
        for ( int round = 0; round < 72; round++ )
        {
            // Add round key
            for ( int i = 0; i < 8; i++ )
            {
                state[i] += keySchedule[(round % 19) * 8 + i];
            }

            // Apply mix operations
            for ( int i = 0; i < 4; i++ )
            {
                MixFunction(ref state[i * 2], ref state[i * 2 + 1],
                    ROTATION_0_0[i], round % 8 == 0);
            }

            // Permute words
            ulong[] newState = new ulong[8];
            for ( int i = 0; i < 8; i++ )
            {
                newState[PERMUTATION[i % 4] + (i / 4) * 4] = state[i];
            }
            state = newState;
        }

        byte[] result = new byte[BLOCK_SIZE];
        for ( int i = 0; i < 8; i++ )
        {
            BitConverter.GetBytes(state[i]).CopyTo(result, i * 8);
        }
        return result;
    }

    private static void MixFunction(ref ulong x0, ref ulong x1, int rotation, bool firstRound)
    {
        if ( firstRound )
        {
            x0 += x1;
            x1 = RotateLeft(x1, rotation) ^ x0;
        }
        else
        {
            x1 = RotateLeft(x1, rotation);
            x0 += x1;
            x1 ^= x0;
        }
    }

    private static ulong RotateLeft(ulong value, int offset)
        => (value << offset) | (value >> (64 - offset));

    private byte[] DecryptBlock(byte[] block, ulong[] keySchedule)
    {
        ulong[] state = new ulong[8];
        for ( int i = 0; i < 8; i++ )
        {
            state[i] = BitConverter.ToUInt64(block, i * 8);
        }

        // Reverse the 72 rounds of mixing
        for ( int round = 71; round >= 0; round-- )
        {
            // Reverse permutation
            ulong[] newState = new ulong[8];
            for ( int i = 0; i < 8; i++ )
            {
                int permIndex = PERMUTATION[i % 4] + (i / 4) * 4;
                newState[i] = state[permIndex];
            }
            state = newState;

            // Reverse mix operations
            for ( int i = 3; i >= 0; i-- )
            {
                UnmixFunction(ref state[i * 2], ref state[i * 2 + 1],
                    ROTATION_0_0[i], round % 8 == 0);
            }

            // Subtract round key
            for ( int i = 0; i < 8; i++ )
            {
                state[i] -= keySchedule[(round % 19) * 8 + i];
            }
        }

        byte[] result = new byte[BLOCK_SIZE];
        for ( int i = 0; i < 8; i++ )
        {
            BitConverter.GetBytes(state[i]).CopyTo(result, i * 8);
        }
        return result;
    }

    private static void UnmixFunction(ref ulong x0, ref ulong x1, int rotation, bool firstRound)
    {
        if ( firstRound )
        {
            x1 ^= x0;
            x1 = RotateRight(x1, rotation);
            x0 -= x1;
        }
        else
        {
            x1 ^= x0;
            x0 -= x1;
            x1 = RotateRight(x1, rotation);
        }
    }

    private static ulong RotateRight(ulong value, int offset)
        => (value >> offset) | (value << (64 - offset));

    private ulong[] GenerateKeySchedule(byte[] key, byte[] tweak)
    {
        // Convert key and tweak to ulongs
        ulong[] k = new ulong[9];  // 8 key words + key parity word
        ulong[] t = new ulong[3];  // 2 tweak words + tweak parity word

        // Load key words
        for ( int i = 0; i < 8; i++ )
        {
            k[i] = BitConverter.ToUInt64(key, i * 8);
        }

        // Load tweak words
        t[0] = BitConverter.ToUInt64(tweak, 0);
        t[1] = BitConverter.ToUInt64(tweak, 8);

        // Calculate parity words
        k[8] = CONST_240;
        for ( int i = 0; i < 8; i++ )
        {
            k[8] ^= k[i];
        }
        t[2] = t[0] ^ t[1];

        // Generate 19 subkeys of 8 words each
        ulong[] schedule = new ulong[19 * 8];
        for ( int s = 0; s < 19; s++ )
        {
            // Calculate subkey values
            for ( int i = 0; i < 8; i++ )
            {
                schedule[s * 8 + i] = k[(s + i) % 9];
            }

            // Add tweak schedule
            schedule[s * 8 + 0] += t[s % 3];
            schedule[s * 8 + 1] += t[(s + 1) % 3];

            // Add round number
            schedule[s * 8 + 2] += (ulong) s;
        }

        return schedule;
    }

}
