using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Token_Generator.Interfaces
{
    public interface IEncoder
    {
        string Encode(byte[] data);
        byte[] Decode(string encodedData);
        bool IsUrlSafe { get; }
    }
}
