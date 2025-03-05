using Token_Generator.Encrypt;
using Token_Generator.Interfaces;

public class EncryptionFactory
{
    private readonly ConfigurationService _configService;
    private readonly Dictionary<string, Func<IEncoder, IEncryption>> _creators;

    public EncryptionFactory(ConfigurationService configService)
    {
        _configService = configService;
        _creators = new Dictionary<string, Func<IEncoder, IEncryption>>
        {
            ["AES_GCM"] = encoder => new AesGcmEncrypt(encoder),
            ["ThreeFish"] = encoder => new ThreefishEncrypt(encoder),
            ["ChaCha20"] = encoder => new ChaCha20Encrypt(encoder),
            ["XChaCha20"] = encoder => new XChaCha20Encrypt(encoder),
            ["Salsa20"] = encoder => new Salsa20Encrypt(encoder),
            ["RC2"] = encoder => new RC2Encrypt(encoder),
            ["TripleDES"] = encoder => new TripleDesEncrypt(encoder)
        };
    }

    public IEncryption Create(string algorithmName)
    {
        if ( !_creators.TryGetValue(algorithmName, out var creator) )
        {
            throw new ArgumentException($"Unknown algorithm: {algorithmName}");
        }

        var encoder = _configService.GetDefaultEncoder(algorithmName);
        return creator(encoder);
    }

    public IEncryption Create(string algorithmName, IEncoder encoder)
    {
        if ( !_creators.TryGetValue(algorithmName, out var creator) )
        {
            throw new ArgumentException($"Unknown algorithm: {algorithmName}");
        }

        return creator(encoder);
    }
}