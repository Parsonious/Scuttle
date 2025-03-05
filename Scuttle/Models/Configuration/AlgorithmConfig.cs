using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Scuttle.Models.Configuration
{
    public class AlgorithmConfig
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int KeySize { get; set; }
        public bool IsLegacy { get; set; }
        public string[] Capabilities { get; set; } = Array.Empty<string>();
        public string DefaultEncoder { get; set; } = "Base64";
    }
}
