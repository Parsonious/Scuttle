using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Scuttle.Interfaces;

namespace Scuttle.Models
{
    internal class EncryptionAlgorithm
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public bool IsLegacy { get; set; }
        public string Description { get; set; } = string.Empty;
    }
}
