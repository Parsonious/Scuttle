using Microsoft.Extensions.Configuration;
using Token_Generator.Encrypt;
using Token_Generator.Interfaces;
using Token_Generator.Models;

internal class ConfigurationService
{
    private readonly Dictionary<string, IEncryption> _implementations = new();
    private readonly List<EncryptionAlgorithm> _algorithms = new();
    private readonly List<EncodingMethod> _encodingMethods = new();

    public IReadOnlyList<EncryptionAlgorithm> Algorithms => _algorithms.AsReadOnly();
    public IReadOnlyList<EncodingMethod> EncodingMethods => _encodingMethods.AsReadOnly();

    public ConfigurationService(IConfiguration config)
    {
        InitializeEncodingMethods();
        InitializeEncryptionAlgorithms();
    }

    private void InitializeEncodingMethods()
    {
        _encodingMethods.AddRange(new[]
        {
            new EncodingMethod
            {
                Name = "Base64",
                DisplayName = "Base64",
                Description = "URL-safe, compact",
                IsUrlSafe = true
            },
            new EncodingMethod
            {
                Name = "Base85",
                DisplayName = "Base85",
                Description = "More compact, not URL-safe",
                IsUrlSafe = false
            },
            new EncodingMethod
            {
                Name = "Base65536",
                DisplayName = "Base65536",
                Description = "Most compact, Unicode-based",
                IsUrlSafe = false
            },
        });
    }

    private void InitializeEncryptionAlgorithms()
    {
        // Modern algorithms
        RegisterAlgorithm(new EncryptionAlgorithm
        {
            Name = "AES_GCM",
            DisplayName = "AES-GCM",
            Description = "Advanced Encryption Standard with Galois/Counter Mode",
            IsLegacy = false
        }, new AesGcmEncrypt());

        RegisterAlgorithm(new EncryptionAlgorithm
        {
            Name = "XChaCha20",
            DisplayName = "XChaCha20",
            Description = "Extended ChaCha20 stream cipher with Poly1305",
            IsLegacy = false
        }, new XChaCha20Encrypt());

        RegisterAlgorithm(new EncryptionAlgorithm
        {
            Name = "ChaCha20",
            DisplayName = "ChaCha20",
            Description = "ChaCha20 stream cipher with Poly1305",
            IsLegacy = false
        }, new ChaCha20Encrypt());

        RegisterAlgorithm(new EncryptionAlgorithm
        {
            Name = "ThreeFish",
            DisplayName = "ThreeFish",
            Description = "ThreeFish block cipher (512-bit)",
            IsLegacy = false
        }, new ThreefishEncrypt());

        // Legacy algorithms
        RegisterAlgorithm(new EncryptionAlgorithm
        {
            Name = "RC2",
            DisplayName = "RC2",
            Description = "RC2 block cipher (legacy)",
            IsLegacy = true
        }, new RC2Encrypt());

        RegisterAlgorithm(new EncryptionAlgorithm
        {
            Name = "TripleDES",
            DisplayName = "Triple DES",
            Description = "Triple DES block cipher (legacy)",
            IsLegacy = true
        }, new TripleDesEncrypt());
    }
    internal void RegisterAlgorithm(EncryptionAlgorithm algorithm, IEncryption implementation)
    {
        _algorithms.Add(algorithm);
        _implementations[algorithm.Name] = implementation;
    }
    internal IEncryption GetImplementation(string name)
        => _implementations.TryGetValue(name, out var impl)
            ? impl
            : throw new KeyNotFoundException($"Encryption algorithm '{name}' not found.");

    internal EncodingMethod GetEncodingMethod(string name)
        => _encodingMethods.FirstOrDefault(m => m.Name == name)
            ?? throw new KeyNotFoundException($"Encoding method '{name}' not found.");
}
