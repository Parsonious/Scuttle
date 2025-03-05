using System.Security.Cryptography;
using System.Text;
using Scuttle.Base;
using Scuttle.Interfaces;

internal class RC2Encrypt : BaseEncryption
{
    private const int KEY_SIZE = 16;    // 128 bits
    private const int IV_SIZE = 8;      // 64 bits

    public RC2Encrypt(IEncoder encoder) : base(encoder)
    {
    }

    public override byte[] Encrypt(byte[] data, byte[] key)
    {
        if ( data == null || data.Length == 0 )
            throw new ArgumentException("Data cannot be null or empty.", nameof(data));

        if ( key == null || key.Length != KEY_SIZE )
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes.", nameof(key));

        byte[] iv = new byte[IV_SIZE];
        RandomNumberGenerator.Fill(iv);

        using var rc2 = RC2.Create();
        rc2.Key = key;
        rc2.IV = iv;

        using var msEncrypt = new MemoryStream();
        // Write IV to the beginning of the stream
        msEncrypt.Write(iv, 0, iv.Length);

        using ( var cryptoStream = new CryptoStream(msEncrypt, rc2.CreateEncryptor(), CryptoStreamMode.Write) )
        using ( var writer = new BinaryWriter(cryptoStream) )
        {
            writer.Write(data.Length); // Write original length
            writer.Write(data);        // Write data
        }

        return msEncrypt.ToArray();
    }

    public override byte[] Decrypt(byte[] encryptedData, byte[] key)
    {
        if ( encryptedData == null || encryptedData.Length < IV_SIZE )
            throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));

        if ( key == null || key.Length != KEY_SIZE )
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes.", nameof(key));

        // Extract IV from the beginning of the encrypted data
        byte[] iv = new byte[IV_SIZE];
        Buffer.BlockCopy(encryptedData, 0, iv, 0, IV_SIZE);

        using var rc2 = RC2.Create();
        rc2.Key = key;
        rc2.IV = iv;

        using var msDecrypt = new MemoryStream(encryptedData, IV_SIZE, encryptedData.Length - IV_SIZE);
        using var cryptoStream = new CryptoStream(msDecrypt, rc2.CreateDecryptor(), CryptoStreamMode.Read);
        using var reader = new BinaryReader(cryptoStream);

        int length = reader.ReadInt32(); // Read original length
        return reader.ReadBytes(length); // Read data
    }

    public override byte[] GenerateKey()
    {
        byte[] key = new byte[KEY_SIZE];
        RandomNumberGenerator.Fill(key);
        return key;
    }
}
