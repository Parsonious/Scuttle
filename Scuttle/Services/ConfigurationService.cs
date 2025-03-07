using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Scuttle.Encoders;
using Scuttle.Interfaces;
using Scuttle.Models;
using Scuttle.Models.Configuration;
using Scuttle.Services;

public class ConfigurationService
{
    private readonly IConfiguration _configuration;
    private readonly EncryptionConfig _encryptionConfig;
    private readonly ILogger<ConfigurationService> _logger;
    private readonly AlgorithmIdentifier _algorithmIdentifier;

    public ConfigurationService(
        IConfiguration configuration,
        ILogger<ConfigurationService> logger,
        AlgorithmIdentifier algorithmIdentifier)
    {
        _configuration = configuration;
        _logger = logger;
        _algorithmIdentifier = algorithmIdentifier;
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
    public AlgorithmMetadata GetAlgorithmById(string algorithmId)
    {
        // Direct mapping from algorithm ID to configuration name
        string configName = algorithmId switch
        {
            "AESG" => "AES_GCM",   
            "CC20" => "ChaCha20",
            "SL20" => "Salsa20",
            "3DES" => "TripleDes",
            "3FSH" => "ThreeFish",
            "RC2_" => "RC2",
            "XCCH" => "XChaCha20", 
            "AES_" => "AES",
            _ => algorithmId
        };

        // First try to find by mapped name (case insensitive)
        try
        {
            // Try to find the algorithm by the mapped name (case-insensitive)
            var algorithm = GetAllAlgorithms().FirstOrDefault(a =>
                a.Name.Equals(configName, StringComparison.OrdinalIgnoreCase));

            if ( algorithm != null )
                return algorithm;

            // If not found by mapped name, try by original ID
            return GetAlgorithmMetadata(configName);
        }
        catch ( KeyNotFoundException )
        {
            // Log at debug level only
            _logger.LogDebug("Algorithm not found by mapped name: {ConfigName}", configName);

            // Try with exact algorithm ID
            var algorithm = GetAllAlgorithms().FirstOrDefault(a =>
                a.Name.Equals(algorithmId, StringComparison.OrdinalIgnoreCase));

            if ( algorithm != null )
                return algorithm;

            // If we couldn't find a match, fall back to default with minimal logging
            var firstAlgo = GetAllAlgorithms().FirstOrDefault() ??
                throw new InvalidOperationException("No encryption algorithms are configured");

            _logger.LogDebug("Using default algorithm: {AlgorithmName}", firstAlgo.Name);
            return firstAlgo;
        }
    }

}
