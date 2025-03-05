using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Scuttle.Models
{
    public record AlgorithmMetadata
    {
        public required string Name { get; init; }
        public required string DisplayName { get; init; }
        public required string Description { get; init; }
        public required int KeySize { get; init; }
        public bool IsLegacy { get; init; }
        public string[] Capabilities { get; init; } = Array.Empty<string>();
    }
}
