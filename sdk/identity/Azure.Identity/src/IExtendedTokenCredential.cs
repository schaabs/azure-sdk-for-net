// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;
using Azure.Core;

namespace Azure.Identity
{
    internal interface IExtendedTokenCredential
    {
        Task<(AccessToken, string)> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken);

        (AccessToken, string) GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken);
    }
}
