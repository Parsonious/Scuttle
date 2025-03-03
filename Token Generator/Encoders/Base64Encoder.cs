using Token_Generator.Interfaces;
using Token_Generator.Base;

namespace Token_Generator.Encoders
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
