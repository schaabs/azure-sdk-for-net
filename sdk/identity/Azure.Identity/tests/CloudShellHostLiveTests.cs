﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Core.Testing;
using Azure.Security.KeyVault.Secrets;
using NUnit.Framework;

namespace Azure.Identity.Tests
{
    public class CloudShellHostLiveTests : RecordedTestBase
    {
        public CloudShellHostLiveTests(bool isAsync) : base(isAsync)
        {
            Sanitizer = new IdentityRecordedTestSanitizer();
        }

        [Test]
        public async Task ManagedIdentityCredenitalWithSystemAssignedIdentity()
        {
            AssertTestEnabled();

            var vaultUri = new Uri(Recording.GetVariableFromEnvironment("IDENTITYTEST_CLOUDSHELLHOST_SYSTEMASSIGNEDVAULT"));

            var cred = CreateInstrumentedManagedIdentityCredential();

            await AssertCredentialVaultAccess(vaultUri, cred);
        }

        [Test]
        public async Task DefaultAzureCredenitalWithSystemAssignedIdentity()
        {
            AssertTestEnabled();

            var vaultUri = new Uri(Recording.GetVariableFromEnvironment("IDENTITYTEST_CLOUDSHELLHOST_SYSTEMASSIGNEDVAULT"));

            var options = new DefaultAzureCredentialOptions() { ExcludeEnvironmentCredential = true, ExcludeSharedTokenCacheCredential = true, ExcludeInteractiveBrowserCredential = true };

            var cred = CreateInstrumentedDefaultAzureCredential(options);

            await AssertCredentialVaultAccess(vaultUri, cred);
        }

        private void AssertTestEnabled()
        {
            if (string.IsNullOrEmpty(Recording.GetVariableFromEnvironment("IDENTITYTEST_CLOUDSHELLHOST_ENABLE")))
            {
                Assert.Ignore();
            }
        }

        private ManagedIdentityCredential CreateInstrumentedManagedIdentityCredential(string clientId = default, TokenCredentialOptions options = default)
        {
            options = Recording.InstrumentClientOptions(options ?? new TokenCredentialOptions());

            var cred = new ManagedIdentityCredential(clientId, options);

            return cred;
        }

        private DefaultAzureCredential CreateInstrumentedDefaultAzureCredential(DefaultAzureCredentialOptions options = default)
        {
            options = Recording.InstrumentClientOptions(options ?? new DefaultAzureCredentialOptions());

            var cred = new DefaultAzureCredential(options);

            return cred;
        }

        private async Task AssertCredentialVaultAccess(Uri vaultUri, TokenCredential credential)
        {
            var kvoptions = Recording.InstrumentClientOptions(new SecretClientOptions());

            var kvclient = new SecretClient(vaultUri, credential, kvoptions);

            KeyVaultSecret secret = await kvclient.GetSecretAsync("identitytestsecret");

            Assert.IsNotNull(secret);
        }
    }
}
