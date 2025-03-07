using Scuttle.Base;
using Scuttle.Interfaces;

namespace Scuttle.Encoders
{
    internal class Base85Encoder : IEncoder
    {
        public bool IsUrlSafe => false;

        public string Encode(byte[] data)
            => Base85.Encode(data);

        public byte[] Decode(string encodedData)
            => Base85.Decode(encodedData);
        /// <summary>
        /// Checks if the string is a valid Base85 format
        /// </summary>
        public bool IsValidFormat(string data)
        {
            if ( string.IsNullOrEmpty(data) )
                return false;

            // Remove whitespace for checking
            data = data.Replace("\r", "").Replace("\n", "").Replace(" ", "");

            // Base85 uses characters from ASCII 33 ('!') to ASCII 117 ('u')
            return data.All(c => c >= '!' && c <= 'u');
        }
    }
}
