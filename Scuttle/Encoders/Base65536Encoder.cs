using Scuttle.Base;
using Scuttle.Interfaces;

namespace Scuttle.Encoders
{
    internal class Base65536Encoder : IEncoder
    {
        public bool IsUrlSafe => false;

        public string Encode(byte[] data)
            => Base65536.Encode(data);

        public byte[] Decode(string encodedData)
            => Base65536.Decode(encodedData);
        /// <summary>
        /// Placeholder Method
        /// Checks if the string is a valid Base65536 format
        /// </summary>
        public bool IsValidFormat(string data)
        {
            if ( string.IsNullOrEmpty(data) )
                return false;

            // Base65536 uses a specific set of Unicode code points
            // This is a simplified validation - ideally we would check against
            // the actual valid Base65536 code points, but for simplicity:
            return data.All(c => c > 128); // Base65536 uses characters outside ASCII range
        }
    }
}
