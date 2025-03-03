using System.Security.Cryptography;
using Token_Generator.Interfaces;
using System.Text;
using Token_Generator.Base;

namespace Token_Generator.Encrypt
{
    internal class ChaCha20Encrypt : BaseEncryption
    {
        private const int KeySize = 32; // 256 bits
        private const int NonceSize = 12;

        public ChaCha20Encrypt(IEncoder encoder) : base(encoder)
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

            using var chacha = new ChaCha20Poly1305(key);
            byte[] ciphertext = new byte[data.Length];
            byte[] tag = new byte[16];

            chacha.Encrypt(nonce, data, ciphertext, tag);

            byte[] result = new byte[NonceSize + ciphertext.Length + tag.Length];
            Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
            Buffer.BlockCopy(ciphertext, 0, result, NonceSize, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, NonceSize + ciphertext.Length, tag.Length);

            return result;
        }

        public override byte[] Decrypt(byte[] encryptedData, byte[] key)
        {
            if ( encryptedData == null || encryptedData.Length < NonceSize + 16 )
                throw new ArgumentException("Invalid encrypted data.", nameof(encryptedData));

            byte[] nonce = new byte[NonceSize];
            Buffer.BlockCopy(encryptedData, 0, nonce, 0, NonceSize);

            int ciphertextLength = encryptedData.Length - NonceSize - 16;
            byte[] ciphertext = new byte[ciphertextLength];
            Buffer.BlockCopy(encryptedData, NonceSize, ciphertext, 0, ciphertextLength);

            byte[] tag = new byte[16];
            Buffer.BlockCopy(encryptedData, NonceSize + ciphertextLength, tag, 0, 16);

            using var chacha = new ChaCha20Poly1305(key);
            byte[] plaintext = new byte[ciphertextLength];
            chacha.Decrypt(nonce, ciphertext, tag, plaintext);

            return plaintext;
        }

        public override byte[] GenerateKey()
        {
            byte[] key = new byte[KeySize];
            RandomNumberGenerator.Fill(key);
            return key;
        }
    }
}
