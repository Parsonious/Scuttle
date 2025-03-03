using System.Security.Cryptography;
using System.Text;
using Token_Generator.Base;
using Token_Generator.Interfaces;

internal class TripleDesEncrypt : BaseEncryption
{

    private const int KEY_SIZE = 24;    // 192 bits
    private const int IV_SIZE = 8;      // 64 bits

    public TripleDesEncrypt(IEncoder encoder) : base(encoder)
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

        using var tdes = TripleDES.Create();
        tdes.Key = key;
        tdes.IV = iv;

        using var msEncrypt = new MemoryStream();
        msEncrypt.Write(iv, 0, iv.Length);

        using ( var cryptoStream = new CryptoStream(msEncrypt, tdes.CreateEncryptor(), CryptoStreamMode.Write) )
        using ( var writer = new BinaryWriter(cryptoStream) )
        {
            writer.Write(data.Length);
            writer.Write(data);
        }

        return msEncrypt.ToArray();
    }

    public override byte[] Decrypt(byte[] encryptedData, byte[] key)
    {
        if ( encryptedData == null || encryptedData.Length < IV_SIZE )
            throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));

        if ( key == null || key.Length != KEY_SIZE )
            throw new ArgumentException($"Key must be {KEY_SIZE} bytes.", nameof(key));

        byte[] iv = new byte[IV_SIZE];
        Buffer.BlockCopy(encryptedData, 0, iv, 0, IV_SIZE);

        using var tdes = TripleDES.Create();
        tdes.Key = key;
        tdes.IV = iv;

        using var msDecrypt = new MemoryStream(encryptedData, IV_SIZE, encryptedData.Length - IV_SIZE);
        using var cryptoStream = new CryptoStream(msDecrypt, tdes.CreateDecryptor(), CryptoStreamMode.Read);
        using var reader = new BinaryReader(cryptoStream);

        int length = reader.ReadInt32();
        return reader.ReadBytes(length);
    }
    public override byte[] GenerateKey()
    {
        byte[] key = new byte[KEY_SIZE];
        RandomNumberGenerator.Fill(key);
        return key;
    }
}
