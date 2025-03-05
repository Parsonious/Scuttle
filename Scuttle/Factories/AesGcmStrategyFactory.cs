using Microsoft.Extensions.Logging;

namespace Scuttle.Encrypt.Strategies.AesGcm
{
    /// <summary>
    /// Factory that selects the optimal AES-GCM implementation for the current hardware
    /// </summary>
    internal static class AesGcmStrategyFactory
    {
        private static IAesGcmStrategy? _cachedStrategy;
        private static readonly object _lock = new();

        /// <summary>
        /// Gets the best available implementation for the current platform
        /// </summary>
        public static IAesGcmStrategy GetBestStrategy(ILogger? logger = null)
        {
            if ( _cachedStrategy != null )
                return _cachedStrategy;

            lock ( _lock )
            {
                if ( _cachedStrategy != null )
                    return _cachedStrategy;

                var strategies = new List<IAesGcmStrategy>();

                // Always add the software fallback strategy since it works on all platforms
                strategies.Add(new AesGcmSoftwareStrategy());
                logger?.LogDebug("Software AES-GCM implementation is available");

                // Check for hardware acceleration
                if ( AesGcmHardwareStrategy.IsSupported )
                {
                    strategies.Add(new AesGcmHardwareStrategy());
                    logger?.LogDebug("Hardware-accelerated AES-GCM implementation is available");
                }

                // Select the strategy with the highest priority
                _cachedStrategy = strategies.OrderByDescending(s => s.Priority).First();

                logger?.LogInformation("Selected AES-GCM implementation: {Description}",
                    _cachedStrategy.Description);

                return _cachedStrategy;
            }
        }

        /// <summary>
        /// Forces the use of a specific implementation type, ignoring hardware support
        /// </summary>
        /// <remarks>
        /// This is primarily useful for testing or in specific scenarios where you want
        /// to bypass the automatic selection.
        /// </remarks>
        internal static void ForceImplementation<T>(ILogger? logger = null) where T : IAesGcmStrategy, new()
        {
            lock ( _lock )
            {
                _cachedStrategy = new T();
                logger?.LogWarning("Forced AES-GCM implementation to: {Description}",
                    _cachedStrategy.Description);
            }
        }

        /// <summary>
        /// Clears the cached strategy, allowing it to be re-selected on next use
        /// </summary>
        internal static void ResetStrategy()
        {
            lock ( _lock )
            {
                _cachedStrategy = null;
            }
        }
    }
}
