// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensions.Msal;

namespace Azure.Identity
{
    internal abstract class MsalClientBase<TClient>
        where TClient : IClientApplicationBase
    {
        private readonly Lazy<Task> _ensureInitAsync;

        /// <summary>
        /// For mocking purposes only.
        /// </summary>
        protected MsalClientBase()
        {
        }

        protected MsalClientBase(CredentialPipeline pipeline, string tenantId, string clientId, ITokenCacheOptions cacheOptions)
        {
            Pipeline = pipeline;

            TenantId = tenantId;

            ClientId = clientId;

            CacheProvider = cacheOptions?.CacheProvider;

            _ensureInitAsync = new Lazy<Task>(InitializeAsync);
        }

        internal string TenantId { get; }

        internal string ClientId { get; }

        internal TokenCacheProvider CacheProvider { get; }

        protected CredentialPipeline Pipeline { get; }

        protected TClient Client { get; private set; }

        protected abstract Task<TClient> CreateClientAsync();

        protected async Task EnsureInitializedAsync(bool async)
        {
            if (async)
            {
                await _ensureInitAsync.Value.ConfigureAwait(false);
            }
            else
            {
#pragma warning disable AZC0102 // Do not use GetAwaiter().GetResult().
                _ensureInitAsync.Value.GetAwaiter().GetResult();
#pragma warning restore AZC0102 // Do not use GetAwaiter().GetResult().
            }
        }

        private async Task InitializeAsync()
        {
            Client = await CreateClientAsync().ConfigureAwait(false);

            if (CacheProvider != null)
            {
                await CacheProvider.RegisterCache(Client.UserTokenCache).ConfigureAwait(false);
            }
        }
    }
}
