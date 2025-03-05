using Scuttle.Encoders;
using Scuttle.Interfaces;

namespace Scuttle.Factories
{
    internal class EncoderFactory
    {
        private readonly Dictionary<string, Func<IEncoder>> _creators;

        public EncoderFactory()
        {
            _creators = new Dictionary<string, Func<IEncoder>>
            {
                ["Base64"] = () => new Base64Encoder(),
                ["Base85"] = () => new Base85Encoder(),
                ["Base65536"] = () => new Base65536Encoder()
            };
        }

        public IEncoder Create(string encoderName)
        {
            if ( _creators.TryGetValue(encoderName, out var creator) )
            {
                return creator();
            }
            throw new ArgumentException($"Unknown encoder: {encoderName}");
        }

        public IReadOnlyCollection<string> GetAvailableEncoders()
            => _creators.Keys;
    }
}
