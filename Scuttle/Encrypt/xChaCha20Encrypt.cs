using System.Security.Cryptography;
using System.Text;
using Token_Generator.Interfaces;
using NSec.Cryptography;
using Token_Generator.Base;

internal class XChaCha20Encrypt : BaseEncryption
{
    private const int KeySize = 32;     // 256 bits
    private const int NonceSize = 24;   // 192 bits for XChaCha20
    private const int TagSize = 16;     // 128 bits for Poly1305

    public XChaCha20Encrypt(IEncoder encoder) :base(encoder)
    {
    }

    public override byte[] Encrypt(byte[] data, byte[] key)
    {
        if ( data == null || data.Length == 0 )
            throw new ArgumentException("Data cannot be null or empty.", nameof(data));

        if ( key == null || key.Length != KeySize )
            throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));

        byte[] nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var xchacha = AeadAlgorithm.XChaCha20Poly1305;
        using ( var keyHandle = Key.Import(xchacha, key, KeyBlobFormat.RawSymmetricKey) )
        {
            byte[] ciphertext = new byte[data.Length + TagSize];
            xchacha.Encrypt(keyHandle, nonce, null, data, ciphertext);

            byte[] result = new byte[NonceSize + ciphertext.Length];
            Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
            Buffer.BlockCopy(ciphertext, 0, result, NonceSize, ciphertext.Length);

            return result;
        }
    }

    public override byte[] Decrypt(byte[] encryptedData, byte[] key)
    {
        if ( encryptedData == null || encryptedData.Length < NonceSize + TagSize )
            throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));

        byte[] nonce = new byte[NonceSize];
        Buffer.BlockCopy(encryptedData, 0, nonce, 0, NonceSize);

        int ciphertextLength = encryptedData.Length - NonceSize;
        byte[] ciphertext = new byte[ciphertextLength];
        Buffer.BlockCopy(encryptedData, NonceSize, ciphertext, 0, ciphertextLength);

        var xchacha = AeadAlgorithm.XChaCha20Poly1305;
        using ( var keyHandle = Key.Import(xchacha, key, KeyBlobFormat.RawSymmetricKey) )
        {
            byte[] plaintext = new byte[ciphertextLength - TagSize];
            xchacha.Decrypt(keyHandle, nonce, null, ciphertext, plaintext);

            return plaintext;
        }
    }
    public override byte[] GenerateKey()
    {
        byte[] key = new byte[KeySize];
        RandomNumberGenerator.Fill(key);
        return key;
    }
}
