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
    }
}
