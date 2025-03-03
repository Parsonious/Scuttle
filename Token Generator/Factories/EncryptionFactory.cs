using Token_Generator.Encrypt;
using Token_Generator.Interfaces;

namespace Token_Generator.Factories
{
    // Factories/EncryptionFactory.cs
    internal class EncryptionFactory
    {
        private readonly Dictionary<string, Func<IEncoder, IEncryption>> _creators;

        public EncryptionFactory()
        {
            _creators = new Dictionary<string, Func<IEncoder, IEncryption>>
            {
                ["AES_GCM"] = encoder => new AesGcmEncrypt(encoder),
                ["ThreeFish"] = encoder => new ThreefishEncrypt(encoder),
                ["ChaCha20"] = encoder => new ChaCha20Encrypt(encoder),
                ["XChaCha20"] = encoder => new XChaCha20Encrypt(encoder),
                ["Salsa20"] = encoder => new Salsa20Encrypt(encoder)
            };
        }

        public IEncryption Create(string algorithmName, IEncoder encoder = null)
        {
            if ( _creators.TryGetValue(algorithmName, out var creator) )
            {
                return creator(encoder);
            }
            throw new ArgumentException($"Unknown algorithm: {algorithmName}");
        }
    }

}
