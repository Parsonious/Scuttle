using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Scuttle.Models
{
    public class BatchOperation
    {
        public string Mode { get; set; } = string.Empty;
        public string? Algorithm { get; set; }
        public string? Encoder { get; set; }
        public string? Title { get; set; }
        public string? Instructions { get; set; }
        public string? Token { get; set; }
        public string? Key { get; set; }
        public string? OutputFile { get; set; }
        public bool Silent { get; set; }
    }
}
