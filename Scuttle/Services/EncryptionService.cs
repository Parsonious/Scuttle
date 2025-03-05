using System.Text;
using Scuttle.Configuration;

public class EncryptionService
{
    private readonly ConfigurationService _config;
    private readonly AlgorithmRegistry _registry;

    public EncryptionService(ConfigurationService config)
    {
        _config = config;
        var factory = new EncryptionFactory(config);
        _registry = new AlgorithmRegistry(factory);
    }

    public (byte[] data, byte[] key) Encrypt(string algorithmName, string data)
    {
        var implementation = _registry.CreateAlgorithm(algorithmName);
        var key = implementation.GenerateKey();
        var dataBytes = Encoding.UTF8.GetBytes(data);
        var encrypted = implementation.Encrypt(dataBytes, key);
        return (encrypted, key);
    }

    public string Decrypt(string algorithmName, byte[] data, byte[] key)
    {
        var implementation = _registry.CreateAlgorithm(algorithmName);
        var decrypted = implementation.Decrypt(data, key);
        return Encoding.UTF8.GetString(decrypted);
    }

    public string EncodeData(byte[] data, string encodingMethod)
    {
        var encoder = _config.GetEncoder(encodingMethod);
        return encoder.Encode(data);
    }

    public byte[] DecodeData(string data, string encodingMethod)
    {
        var encoder = _config.GetEncoder(encodingMethod);
        return encoder.Decode(data);
    }
}
