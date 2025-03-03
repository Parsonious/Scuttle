using Token_Generator.Base;
using Token_Generator.Interfaces;

namespace Token_Generator.Encoders
{
    internal class Base65536Encoder : IEncoder
    {
        public bool IsUrlSafe => false;

        public string Encode(byte[] data)
            => Base65536.Encode(data);

        public byte[] Decode(string encodedData)
            => Base65536.Decode(encodedData);
    }
}
