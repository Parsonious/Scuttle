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
    }
}
