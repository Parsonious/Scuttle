using Microsoft.Extensions.Logging;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics.Arm;

namespace Scuttle.Encrypt.Strategies.ThreeFish
{
    /// <summary>
    /// Factory for creating the optimal ThreeFish implementation based on hardware capabilities
    /// </summary>
    internal static class ThreeFishStrategyFactory
    {
        private static IThreeFishStrategy? _cachedStrategy;
        private static readonly object _lock = new object();

        /// <summary>
        /// Gets the optimal ThreeFish implementation for the current hardware
        /// </summary>
        public static IThreeFishStrategy GetBestStrategy(ILogger? logger = null)
        {
            if ( _cachedStrategy != null )
                return _cachedStrategy;

            lock ( _lock )
            {
                if ( _cachedStrategy != null )
                    return _cachedStrategy;

                var strategies = new List<IThreeFishStrategy>();

                // Always add scalar strategy as fallback
                strategies.Add(new ThreeFishScalarStrategy());
                logger?.LogDebug("ThreeFish scalar implementation is available");

                // Check for ARM NEON/AdvSimd support
                if ( ThreeFishAdvSimdStrategy.IsSupported )
                {
                    strategies.Add(new ThreeFishAdvSimdStrategy());
                    logger?.LogDebug("ThreeFish ARM AdvSimd implementation is available");
                }

                // Check for Intel AVX2 support
                if ( ThreeFishAvx2Strategy.IsSupported )
                {
                    strategies.Add(new ThreeFishAvx2Strategy());
                    logger?.LogDebug("ThreeFish AVX2 implementation is available");
                }
                // Check for SSE2 support
                else if ( ThreeFishSse2Strategy.IsSupported )
                {
                    strategies.Add(new ThreeFishSse2Strategy());
                    logger?.LogDebug("ThreeFish SSE2 implementation is available");
                }

                // Select the strategy with highest priority
                _cachedStrategy = strategies.OrderByDescending(s => s.Priority).First();

                logger?.LogInformation("Selected ThreeFish implementation: {Description}",
                    _cachedStrategy.Description);

                return _cachedStrategy;
            }
        }

        /// <summary>
        /// Forces the use of a specific implementation type, ignoring hardware support
        /// </summary>
        internal static void ForceImplementation<T>(ILogger? logger = null) where T : IThreeFishStrategy, new()
        {
            lock ( _lock )
            {
                _cachedStrategy = new T();
                logger?.LogWarning("Forced ThreeFish implementation to: {Description}",
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
