// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Azure.Identity
{
    /// <summary>
    /// Options used to configure the <see cref="ClientCertificateCredential"/>.
    /// </summary>
    public class ClientCertificateCredentialOptions : TokenCredentialOptions, ITokenCacheOptions
    {
        /// <summary>
        /// Specifies the <see cref="TokenCacheProvider"/> which is use to persist and read the token cache for the credential.
        /// </summary>
        public TokenCacheProvider CacheProvider { get; set; }

        /// <summary>
        /// Will include x5c header to enable subject name / issuer based authentication for the <see cref="ClientCertificateCredential"/>.
        /// </summary>
        public bool IncludeX5CCliamHeader { get; set; }
    }
}
