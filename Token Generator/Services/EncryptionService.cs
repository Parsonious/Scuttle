using System.Text;
using Token_Generator.Base;

public class EncryptionService
{
    private readonly ConfigurationService _config;

    public EncryptionService(ConfigurationService config)
    {
        _config = config;
    }

    public (byte[] data, byte[] key) Encrypt(string algorithmName, string data)
    {
        var implementation = _config.GetImplementation(algorithmName);
        var key = implementation.GenerateKey();
        var dataBytes = Encoding.UTF8.GetBytes(data);
        var encrypted = implementation.Encrypt(dataBytes, key);
        return (encrypted, key);
    }

    public string Decrypt(string algorithmName, byte[] data, byte[] key)
    {
        var implementation = _config.GetImplementation(algorithmName);
        var decrypted = implementation.Decrypt(data, key);
        return Encoding.UTF8.GetString(decrypted);
    }

    public string EncodeData(byte[] data, string encodingMethod)
    {
        return encodingMethod switch
        {
            "Base64" => Base64.UrlEncode(data),
            "Base85" => Base85.Encode(data),
            "Base65536" => Base65536.Encode(data),
            _ => throw new ArgumentException($"Unknown encoding method: {encodingMethod}")
        };
    }

    public byte[] DecodeData(string data, string encodingMethod)
    {
        return encodingMethod switch
        {
            "Base64" => Base64.UrlDecode(data),
            "Base85" => Base85.Decode(data),
            "Base65536" => Base65536.Decode(data),
            _ => throw new ArgumentException($"Unknown encoding method: {encodingMethod}")
        };
    }
}
