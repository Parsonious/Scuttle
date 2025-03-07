using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Scuttle.Interfaces
{
    public interface IEncoder
    {
        string Encode(byte[] data);
        byte[] Decode(string encodedData);
        bool IsUrlSafe { get; }
        
        /// <summary>
        /// Checks if the given string is valid in this encoding format
        /// </summary>
        /// <param name="data">String to check</param>
        /// <returns>True if the string is valid in this encoding format</returns>
        bool IsValidFormat(string data);
    }
}
