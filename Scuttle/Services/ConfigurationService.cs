using Microsoft.Extensions.Configuration;
using Scuttle.Encoders;
using Scuttle.Interfaces;
using Scuttle.Models;
using Scuttle.Models.Configuration;
using Scuttle.Models.Scuttle.Models;

public class ConfigurationService
{
    private readonly IConfiguration _configuration;
    private readonly EncryptionConfig _encryptionConfig;

    public ConfigurationService(IConfiguration configuration)
    {
        _configuration = configuration;
        _encryptionConfig = configuration.GetSection("Encryption").Get<EncryptionConfig>()
            ?? throw new InvalidOperationException("Encryption configuration is missing");
    }
    public IEncoder GetEncoder(string name)
    {
        if ( !_encryptionConfig.Encoders.TryGetValue(name, out var config) )
        {
            throw new KeyNotFoundException($"Encoder '{name}' not found in configuration");
        }

        return name switch
        {
            "Base64" => new Base64Encoder(),
            "Base85" => new Base85Encoder(),
            "Base65536" => new Base65536Encoder(),
            _ => throw new NotSupportedException($"Encoder '{name}' is not supported")
        };
    }

    public IEncoder GetDefaultEncoder(string algorithmName)
    {
        if ( !_encryptionConfig.Algorithms.TryGetValue(algorithmName, out var config) )
        {
            return GetEncoder(_encryptionConfig.DefaultEncoder);
        }
        return GetEncoder(config.DefaultEncoder);
    }

    public AlgorithmMetadata GetAlgorithmMetadata(string name)
    {
        if ( !_encryptionConfig.Algorithms.TryGetValue(name, out var config) )
        {
            throw new KeyNotFoundException($"Algorithm '{name}' not found in configuration");
        }

        return new AlgorithmMetadata
        {
            Name = config.Name,
            DisplayName = config.DisplayName,
            Description = config.Description,
            KeySize = config.KeySize,
            IsLegacy = config.IsLegacy,
            Capabilities = config.Capabilities ?? Array.Empty<string>()
        };
    }

    public IEnumerable<AlgorithmMetadata> GetAllAlgorithms()
    {
        return _encryptionConfig.Algorithms.Values.Select(config => new AlgorithmMetadata
        {
            Name = config.Name,
            DisplayName = config.DisplayName,
            Description = config.Description,
            KeySize = config.KeySize,
            IsLegacy = config.IsLegacy,
            Capabilities = config.Capabilities
        });
    }

    public IEnumerable<EncoderMetadata> GetAllEncoders()
    {
        return _encryptionConfig.Encoders.Values.Select(config => new EncoderMetadata
        {
            Name = config.Name,
            DisplayName = config.DisplayName,
            Description = config.Description,
            IsUrlSafe = config.IsUrlSafe
        });
    }
}
