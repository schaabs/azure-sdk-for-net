// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Azure.Core;
using Azure.Core.Pipeline;
using Microsoft.Identity.Client;
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using System.Text;

namespace Azure.Identity
{
    /// <summary>
    /// Authenticates using tokens in the local cache shared between Microsoft applications.
    /// </summary>
    public class SharedTokenCacheCredential : TokenCredential, IExtendedTokenCredential
    {
        private const string MultipleAccountsErrorMessage = "Multiple accounts were discovered in the token cache. Set the AZURE_USERNAME environment variable to the preferred username, or specify it when constructing SharedTokenCacheCredential.";

        private readonly IPublicClientApplication _pubApp;
        private readonly CredentialPipeline _pipeline;
        private readonly string _username;
        private readonly Lazy<Task<(IAccount, string)>> _account;
        private readonly MsalCacheReader _cacheReader;

        private string _errorMessage;

        /// <summary>
        /// Creates a new SharedTokenCacheCredential which will authenticate users with the specified application.
        /// </summary>
        public SharedTokenCacheCredential()
            : this(null, null)
        {

        }

        /// <summary>
        /// Creates a new SharedTokenCacheCredential with the specifeid options, which will authenticate users with the specified application.
        /// </summary>
        /// <param name="username">The username of the user to authenticate</param>
        /// <param name="options">The client options for the newly created SharedTokenCacheCredential</param>
        public SharedTokenCacheCredential(string username, TokenCredentialOptions options = default)
        {
            _username = username;

            _pipeline = CredentialPipeline.GetInstance(options);

            _pubApp = _pipeline.CreateMsalPublicClient(Constants.DeveloperSignOnClientId);

            _cacheReader = new MsalCacheReader(_pubApp.UserTokenCache, Constants.SharedTokenCacheFilePath, Constants.SharedTokenCacheAccessRetryCount, Constants.SharedTokenCacheAccessRetryDelay);

            _account = new Lazy<Task<(IAccount, string)>>(GetAccountAsync);
        }

        /// <summary>
        /// Obtains an <see cref="AccessToken"/> token for a user account silently if the user has already authenticated to another Microsoft application participating in SSO through the MSAL cache
        /// </summary>
        /// <param name="requestContext">The details of the authentication request.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> controlling the request lifetime</param>
        /// <returns>An <see cref="AccessToken"/> which can be used to authenticate service client calls</returns>
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken = default)
        {
            (AccessToken token, _) = GetTokenImplAsync(requestContext, cancellationToken).GetAwaiter().GetResult();

            return token;
        }

        /// <summary>
        /// Obtains an <see cref="AccessToken"/> token for a user account silently if the user has already authenticated to another Microsoft application participating in SSO through the MSAL cache
        /// </summary>
        /// <param name="requestContext">The details of the authentication request.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> controlling the request lifetime</param>
        /// <returns>An <see cref="AccessToken"/> which can be used to authenticate service client calls</returns>
        public override async Task<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken = default)
        {
            (AccessToken token, _) = await GetTokenImplAsync(requestContext, cancellationToken).ConfigureAwait(false);

            return token;
        }

        (AccessToken, string) IExtendedTokenCredential.GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<(AccessToken, string)> IExtendedTokenCredential.GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        private async Task<(AccessToken, string)> GetTokenImplAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            using DiagnosticScope scope = _pipeline.Diagnostics.CreateScope("Azure.Identity.SharedTokenCacheCredential.GetToken");

            scope.Start();

            try
            {
                try
                {
                    (IAccount account, string message) = await _account.Value.ConfigureAwait(false);

                    if (account != null)
                    {
                        AuthenticationResult result = await _pubApp.AcquireTokenSilent(requestContext.Scopes, account).ExecuteAsync(cancellationToken).ConfigureAwait(false);

                        return (new AccessToken(result.AccessToken, result.ExpiresOn), null);
                    }
                }
                catch (MsalUiRequiredException)
                {
                    _errorMessage = $"Token aquisition failed for user {_username}. To fix, reauthenticate through tooling supporting azure developer single sign on.";
                } // account cannot be silently authenticated

            }
            catch (Exception e)
            {
                scope.Failed(e);

                throw new AuthenticationFailedException(Constants.AuthenticationUnhandledExceptionMessage, e);
            }

            return (default, _errorMessage);
        }

        private async Task<(IAccount, string)> GetAccountAsync()
        {
            IAccount account = null;

            IEnumerable<IAccount> accounts = await _pubApp.GetAccountsAsync().ConfigureAwait(false);

            try
            {
                if (string.IsNullOrEmpty(_username))
                {
                    account = accounts.Single();
                }
                else
                {
                    account = accounts.Where(a => a.Username == _username).First();
                }
            }
            catch (InvalidOperationException)
            {
                if (string.IsNullOrEmpty(_username))
                {
                    _errorMessage = $"{MultipleAccountsErrorMessage}\n Discovered Accounts: [ {string.Join(", ", accounts.Select(a => a.Username))} ]";
                }
                else
                {
                    _errorMessage = $"User account '{_username}' was not found in the shared token cache.\n  Discovered Accounts: [ {string.Join(", ", accounts.Select(a => a.Username))} ]";
                }
            }

            return (account, _errorMessage);
        }

    }
}
