using Scuttle.Interfaces;
using Scuttle.Base;

namespace Scuttle.Encoders
{
    public class Base64Encoder : IEncoder
    {
        public bool IsUrlSafe => true;

        public string Encode(byte[] data)
            => Base64.UrlEncode(data);

        public byte[] Decode(string encodedData)
            => Base64.UrlDecode(encodedData);
        /// <summary>
        /// Checks if the string is a valid Base64 format
        /// </summary>
        public bool IsValidFormat(string test)
        {
            if ( string.IsNullOrEmpty(test) )
                return false;

            // Remove any whitespace that might be in the string
            test = test.Replace("\r", "").Replace("\n", "").Replace(" ", "");

            // Quick check: Base64 strings have a length that's a multiple of 4
            // (they might have padding '=' characters at the end)
            if ( test.Length % 4 != 0 )
                return false;

            // Check if the string contains only valid Base64 characters
            return test.All(c =>
                (c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') ||
                c == '+' || c == '/' || c == '=');
        }
    }
}
