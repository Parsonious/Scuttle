namespace Scuttle.Models
{
    namespace Scuttle.Models
    {
        public record EncoderMetadata
        {
            public required string Name { get; init; }
            public required string DisplayName { get; init; }
            public required string Description { get; init; }
            public required bool IsUrlSafe { get; init; }
        }
    }
}
