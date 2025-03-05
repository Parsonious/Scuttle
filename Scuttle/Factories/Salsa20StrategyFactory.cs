using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Scuttle.Encrypt.Strategies.Salsa20;
using System.Collections.Generic;
using System.Linq;

namespace Scuttle.Factories
{
    /// <summary>
    /// Factory that selects the optimal Salsa20 implementation for the current hardware
    /// </summary>
    internal static class Salsa20StrategyFactory
    {
        private static ISalsa20Strategy? _cachedStrategy;
        private static readonly object _lock = new();

        /// <summary>
        /// Gets the best available implementation for the current platform
        /// </summary>
        public static ISalsa20Strategy GetBestStrategy(ILogger? logger = null)
        {
            if ( _cachedStrategy != null )
                return _cachedStrategy;

            lock ( _lock )
            {
                if ( _cachedStrategy != null )
                    return _cachedStrategy;

                var strategies = new List<ISalsa20Strategy>();

                // Try to create each strategy in order of preference
                if ( Salsa20Avx2Strategy.IsSupported )
                {
                    strategies.Add(new Salsa20Avx2Strategy());
                    logger?.LogDebug("AVX2 Salsa20 implementation is available");
                }

                if ( Salsa20Sse2Strategy.IsSupported )
                {
                    strategies.Add(new Salsa20Sse2Strategy());
                    logger?.LogDebug("SSE2 Salsa20 implementation is available");
                }

                if ( Salsa20AdvSimdStrategy.IsSupported )
                {
                    strategies.Add(new Salsa20AdvSimdStrategy());
                    logger?.LogDebug("ARM NEON Salsa20 implementation is available");
                }

                // Always add the fallback strategy
                strategies.Add(new Salsa20ScalarStrategy());
                logger?.LogDebug("Scalar Salsa20 implementation is available");

                // Select the strategy with the highest priority
                _cachedStrategy = strategies.OrderByDescending(s => s.Priority).First();

                logger?.LogInformation("Selected Salsa20 implementation: {Description}",
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
        internal static void ForceImplementation<T>(ILogger? logger = null) where T : ISalsa20Strategy, new()
        {
            lock ( _lock )
            {
                _cachedStrategy = new T();
                logger?.LogWarning("Forced Salsa20 implementation to: {Description}",
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
