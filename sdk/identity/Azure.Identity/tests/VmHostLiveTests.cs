// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
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
            if (string.IsNullOrEmpty(Recording.GetVariableFromEnvironment("IDENTITYTEST_IMDSTEST_ENABLE")))
            {
                Assert.Ignore();
            }

            var vaultUri = new Uri(Recording.GetVariableFromEnvironment("IDENTITYTEST_IMDSTEST_SYSTEMASSIGNEDVAULT"));

            var cred = CreateInstrumentedManagedIdentityCredential();

            var kvoptions = Recording.InstrumentClientOptions(new SecretClientOptions());

            var kvclient = InstrumentClient(new SecretClient(vaultUri, cred, kvoptions));

            KeyVaultSecret secret = await kvclient.GetSecretAsync("identitytestsecret");

            Assert.IsNotNull(secret);
        }

        [NonParallelizable]
        [Test]
        public async Task ManagedIdentityCredenitalWithUserAssignedIdentity()
        {
            if (string.IsNullOrEmpty(Recording.GetVariableFromEnvironment("IDENTITYTEST_IMDSTEST_ENABLE")))
            {
                Assert.Ignore();
            }

            var vaultUri = new Uri(Recording.GetVariableFromEnvironment("IDENTITYTEST_IMDSTEST_USERASSIGNEDVAULT"));

            var clientId = Recording.GetVariableFromEnvironment("IDENTITYTEST_IMDSTEST_CLIENTID");

            var cred = CreateInstrumentedManagedIdentityCredential(clientId);

            var kvoptions = Recording.InstrumentClientOptions(new SecretClientOptions());

            var kvclient = new SecretClient(vaultUri, cred, kvoptions);

            KeyVaultSecret secret = await kvclient.GetSecretAsync("identitytestsecret");

            Assert.IsNotNull(secret);
        }

        private ManagedIdentityCredential CreateInstrumentedManagedIdentityCredential(string clientId = null, TokenCredentialOptions options = null)
        {
            options = Recording.InstrumentClientOptions(options ?? new TokenCredentialOptions());

            var cred = new ManagedIdentityCredential(clientId, options);

            return cred;
        }
    }
}
