using Scuttle.Interfaces;
using Scuttle.Base;

namespace Scuttle.Encoders
{
    internal class Base64Encoder : IEncoder
    {
        public bool IsUrlSafe => true;

        public string Encode(byte[] data)
            => Base64.UrlEncode(data);

        public byte[] Decode(string encodedData)
            => Base64.UrlDecode(encodedData);
    }
}
