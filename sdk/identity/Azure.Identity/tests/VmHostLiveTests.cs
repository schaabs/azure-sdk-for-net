// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Core.Testing;
using Azure.Identity.Tests.Mock;
using Azure.Security.KeyVault.Secrets;
using NUnit.Framework;

namespace Azure.Identity.Tests
{
    public class VmHostLiveTests : RecordedTestBase
    {
        public VmHostLiveTests(bool isAsync) : base(isAsync)
        {
            Sanitizer = new IdentityRecordedTestSanitizer();
        }

        [OneTimeSetUp]
        public void ResetManagedIdenityClient()
        {
            if (Mode == RecordedTestMode.Playback)
            {
                ManagedIdentityClient.ConfigureForImds();
            }
        }

        [NonParallelizable]
        [Test]
        public async Task ManagedIdentityCredenitalWithSystemAssignedIdentity()
        {
            AssertTestEnabled();

            var vaultUri = new Uri(Recording.GetVariableFromEnvironment("IDENTITYTEST_VMHOST_SYSTEMASSIGNEDVAULT"));

            var cred = CreateInstrumentedManagedIdentityCredential();

            await AssertCredentialVaultAccess(vaultUri, cred);
        }

        [NonParallelizable]
        [Test]
        public async Task ManagedIdentityCredenitalWithUserAssignedIdentity()
        {
            AssertTestEnabled();

            var vaultUri = new Uri(Recording.GetVariableFromEnvironment("IDENTITYTEST_VMHOST_USERASSIGNEDVAULT"));

            var clientId = Recording.GetVariableFromEnvironment("IDENTITYTEST_VMHOST_CLIENTID");

            var cred = CreateInstrumentedManagedIdentityCredential(clientId);

            await AssertCredentialVaultAccess(vaultUri, cred);
        }

        [NonParallelizable]
        [Test]
        public async Task DefaultAzureCredenitalWithSystemAssignedIdentity()
        {
            AssertTestEnabled();

            var vaultUri = new Uri(Recording.GetVariableFromEnvironment("IDENTITYTEST_VMHOST_SYSTEMASSIGNEDVAULT"));

            var options = new DefaultAzureCredentialOptions() { ExcludeEnvironmentCredential = true, ExcludeSharedTokenCacheCredential = true, ExcludeInteractiveBrowserCredential = true };

            var cred = CreateInstrumentedDefaultAzureCredential(options);

            await AssertCredentialVaultAccess(vaultUri, cred);
        }

        [NonParallelizable]
        [Test]
        public async Task DefaultAzureCredenitalWithUserAssignedIdentity()
        {
            AssertTestEnabled();

            var vaultUri = new Uri(Recording.GetVariableFromEnvironment("IDENTITYTEST_VMHOST_USERASSIGNEDVAULT"));

            var clientId = Recording.GetVariableFromEnvironment("IDENTITYTEST_VMHOST_CLIENTID");

            var options = new DefaultAzureCredentialOptions() { ExcludeEnvironmentCredential = true, ExcludeSharedTokenCacheCredential = true, ExcludeInteractiveBrowserCredential = true, ManagedIdentityClientId = clientId };

            var cred = CreateInstrumentedDefaultAzureCredential(options);

            await AssertCredentialVaultAccess(vaultUri, cred);
        }

        private void AssertTestEnabled()
        {
            if (string.IsNullOrEmpty(Recording.GetVariableFromEnvironment("IDENTITYTEST_VMHOST_ENABLE")))
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
