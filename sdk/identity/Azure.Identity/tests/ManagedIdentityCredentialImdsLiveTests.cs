// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Azure.Core.Testing;
using Azure.Security.KeyVault.Secrets;
using NUnit.Framework;

namespace Azure.Identity.Tests
{
    public class ManagedIdentityCredentialImdsLiveTests : ClientTestBase
    {
        public ManagedIdentityCredentialImdsLiveTests(bool isAsync) : base(isAsync)
        {
        }

        [SetUp]
        public void ResetManagedIdenityClient()
        {
            typeof(ManagedIdentityClient).GetField("s_msiType", BindingFlags.NonPublic | BindingFlags.Static).SetValue(null, 0);
            typeof(ManagedIdentityClient).GetField("s_endpoint", BindingFlags.NonPublic | BindingFlags.Static).SetValue(null, null);
        }

        [Test]
        public async Task ValidateImdsSystemAssignedIdentity()
        {
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("IDENTITYTEST_IMDSTEST_ENABLE")))
            {
                Assert.Ignore();
            }

            var vaultUri = new Uri(Environment.GetEnvironmentVariable("IDENTITYTEST_IMDSTEST_SYSTEMASSIGNEDVAULT"));

            var cred = new ManagedIdentityCredential();

            var kvclient = InstrumentClient(new SecretClient(vaultUri, cred));

            KeyVaultSecret secret = await kvclient.GetSecretAsync("identitytestsecret");

            Assert.IsNotNull(secret);
        }


        [Test]
        public async Task ValidateImdsUserAssignedIdentity()
        {
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("IDENTITYTEST_IMDSTEST_ENABLE")))
            {
                Assert.Ignore();
            }

            var vaultUri = new Uri(Environment.GetEnvironmentVariable("IDENTITYTEST_IMDSTEST_USERASSIGNEDVAULT"));

            var clientId = Environment.GetEnvironmentVariable("IDENTITYTEST_IMDSTEST_CLIENTID");

            var cred = new ManagedIdentityCredential(clientId: clientId);

            var kvclient = InstrumentClient(new SecretClient(vaultUri, cred));

            KeyVaultSecret secret = await kvclient.GetSecretAsync("identitytestsecret");

            Assert.IsNotNull(secret);
        }
    }
}
