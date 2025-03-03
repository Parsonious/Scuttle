using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Token_Generator.Factories;
using Token_Generator.Interfaces;
using Token_Generator.Models;

namespace Token_Generator.Configuration
{
    internal class AlgorithmRegistry
    {
        private readonly Dictionary<string, AlgorithmMetadata> _algorithms;
        private readonly EncryptionFactory _factory;

        public AlgorithmRegistry(EncryptionFactory factory)
        {
            _factory = factory;
            _algorithms = new Dictionary<string, AlgorithmMetadata>
            {
                ["AES_GCM"] = new AlgorithmMetadata
                {
                    Name = "AES_GCM",
                    DisplayName = "AES-GCM",
                    Description = "Advanced Encryption Standard with Galois/Counter Mode",
                    KeySize = 32,
                    IsLegacy = false,
                    Capabilities = new[] { "AEAD" }
                },
                ["XChaCha20"] = new AlgorithmMetadata
                {
                    Name = "XChaCha20",
                    DisplayName = "XChaCha20",
                    Description = "Extended ChaCha20 stream cipher with Poly1305",
                    KeySize = 32,
                    IsLegacy = false,
                    Capabilities = new[] { "AEAD", "STREAM" }
                },
                ["ChaCha20"] = new AlgorithmMetadata
                {
                    Name = "ChaCha20",
                    DisplayName = "ChaCha20",
                    Description = "ChaCha20 stream cipher with Poly1305",
                    KeySize = 32,
                    IsLegacy = false,
                    Capabilities = new[] { "AEAD", "STREAM" }
                },
                ["ThreeFish"] = new AlgorithmMetadata
                {
                    Name = "ThreeFish",
                    DisplayName = "ThreeFish",
                    Description = "ThreeFish block cipher (512-bit)",
                    KeySize = 64,
                    IsLegacy = false,
                    Capabilities = new[] { "BLOCK" }
                },
                ["Salsa20"] = new AlgorithmMetadata
                {
                    Name = "Salsa20",
                    DisplayName = "Salsa20",
                    Description = "Salsa20 stream cipher",
                    KeySize = 32,
                    IsLegacy = false,
                    Capabilities = new[] { "STREAM" }
                }
            };
        }

        public IReadOnlyCollection<AlgorithmMetadata> GetAllAlgorithms()
            => _algorithms.Values;

        public IReadOnlyCollection<AlgorithmMetadata> GetModernAlgorithms()
            => _algorithms.Values.Where(a => !a.IsLegacy).ToList();

        public IEncryption CreateAlgorithm(string name, IEncoder encoder = null)
            => _factory.Create(name, encoder);

        public AlgorithmMetadata GetMetadata(string name)
            => _algorithms.TryGetValue(name, out var metadata)
                ? metadata
                : throw new KeyNotFoundException($"Algorithm '{name}' not found.");
    }
}
