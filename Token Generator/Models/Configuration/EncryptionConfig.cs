using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Token_Generator.Models.Configuration
{
    public class EncryptionConfig
    {
        public string DefaultEncoder { get; set; } = "Base64";
        public Dictionary<string, AlgorithmConfig> Algorithms { get; set; } = new();
        public Dictionary<string, EncoderConfig> Encoders { get; set; } = new();
    }
}
