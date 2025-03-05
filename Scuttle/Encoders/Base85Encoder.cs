using Token_Generator.Base;
using Token_Generator.Interfaces;

namespace Token_Generator.Encoders
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
