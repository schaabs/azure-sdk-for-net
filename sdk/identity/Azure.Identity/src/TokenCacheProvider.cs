// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace Azure.Identity
{
    /// <summary>
    /// Implementations of <see cref="TokenCacheProvider"/> can persist and read serialized token cache data.
    /// </summary>
    public abstract class TokenCacheProvider
    {
        /// <summary>
        /// Reads serialized token cache data from it's persisted state.
        /// </summary>
        /// <returns>Returns the serialized token cache data.</returns>
        public abstract Task<byte[]> ReadAsync();

        /// <summary>
        /// Writes serialized token cache data to it's persisted state.
        /// </summary>
        /// <param name="bytes">The serialized token cache data to be persisted.</param>
        public abstract Task WriteAsync(byte[] bytes);

        internal virtual Task RegisterCache(bool async, ITokenCache tokenCache)
        {
            tokenCache.SetBeforeAccessAsync(OnBeforeAccessAsync);

            tokenCache.SetAfterAccessAsync(OnAfterAccessAsync);

            return Task.CompletedTask;
        }

        private async Task OnBeforeAccessAsync(TokenCacheNotificationArgs args)
        {
            args.TokenCache.DeserializeMsalV3(await ReadAsync().ConfigureAwait(false));
        }

        private async Task OnAfterAccessAsync(TokenCacheNotificationArgs args)
        {
            await WriteAsync(args.TokenCache.SerializeMsalV3()).ConfigureAwait(false);
        }
    }
}
