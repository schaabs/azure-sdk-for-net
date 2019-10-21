// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading.Tasks;
using Azure.Core;
using NUnit.Framework;

namespace Azure.Identity.Tests
{
    public class SharedTokenCacheCredentialTests
    {
        [Test]
        public async Task ValidateSingleAccount()
        {
            var cred = new SharedTokenCacheCredential(null, null);

            AccessToken token = await cred.GetTokenAsync(new TokenRequestContext(new string[] { "https://vault.azure.net/.default" }));

            Assert.IsNotNull(token.Token);
        }

        [Test]
        public async Task ValidateUsernameSpecified()
        {
            var cred = new SharedTokenCacheCredential("sschaab@microsoft.com");

            AccessToken token = await cred.GetTokenAsync(new TokenRequestContext(new string[] { "https://vault.azure.net/.default" }));

            Assert.IsNotNull(token.Token);
        }
    }
}
