using System.Text;
using Token_Generator.Interfaces;
using Token_Generator.Encoders;

namespace Token_Generator.Base
{
    internal abstract class BaseEncryption : IEncryption
    {
        protected readonly IEncoder DefaultEncoder;

        protected BaseEncryption(IEncoder encoder)
        {
            DefaultEncoder = encoder ?? new Base64Encoder();
        }

        public abstract byte[] Encrypt(byte[] data, byte[] key);
        public abstract byte[] Decrypt(byte[] encryptedData, byte[] key);
        public abstract byte[] GenerateKey();

        public virtual string EncryptAndEncode(string data, byte[] key)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            byte[] encrypted = Encrypt(dataBytes, key);
            return DefaultEncoder.Encode(encrypted);
        }

        public virtual string DecodeAndDecrypt(string encodedData, byte[] key)
        {
            byte[] encryptedBytes = DefaultEncoder.Decode(encodedData);
            byte[] decrypted = Decrypt(encryptedBytes, key);
            return Encoding.UTF8.GetString(decrypted);
        }
    }
}
