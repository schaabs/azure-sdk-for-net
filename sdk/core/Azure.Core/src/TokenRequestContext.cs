// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Azure.Core
{
    /// <summary>
    /// Contains the details of an authentication token request.
    /// </summary>
    public readonly struct TokenRequestContext
    {
        /// <summary>
        /// Creates a new TokenRequest with the specified scopes.
        /// </summary>
        /// <param name="scopes">The scopes required for the token.</param>
        /// <param name="parentRequestId">The <see cref="Request.ClientRequestId"/> of the request requiring a token for authentication, if applicable.</param>
        /// <param name="claims">Additional claims required for the token.</param>
        public TokenRequestContext(string[] scopes, string? parentRequestId = default, string? claims = default)
        {
            Scopes = scopes;
            HttpMessage = default;
            Claims = claims;
            ParentRequestId = parentRequestId;
        }

        /// <summary>
        /// Creates a new TokenRequest with the specified scopes.
        /// </summary>
        /// <param name="scopes">The scopes required for the token.</param>
        /// <param name="httpMessage">The <see cref="HttpMessage"/> of the request requiring a token for authentication, if applicable.</param>
        /// <param name="claims">Additional claims required for the token.</param>
        public TokenRequestContext(string[] scopes, HttpMessage? httpMessage = default, string? claims = default)
            : this(scopes, httpMessage?.Request?.ClientRequestId, claims)
        {
            HttpMessage = httpMessage;
        }

        /// <summary>
        /// The scopes required for the token.
        /// </summary>
        public string[] Scopes { get; }

        /// <summary>
        /// Additional claims required for the token.
        /// </summary>
        public string? Claims { get; }

        /// <summary>
        /// The <see cref="Request.ClientRequestId"/> of the request requiring a token for authentication, if applicable.
        /// </summary>
        public string? ParentRequestId { get; }

        /// <summary>
        /// The <see cref="HttpMessage"/> of the request requiring a token for authentication, if applicable.
        /// </summary>
        public HttpMessage? HttpMessage { get; }
    }
}
