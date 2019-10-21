﻿// Copyright (c) Microsoft Corporation. All rights reserved.
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
using Azure.Core.Diagnostics;

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
        private readonly Lazy<Task<(IAccount, Exception)>> _account;
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

            _account = new Lazy<Task<(IAccount, Exception)>>(GetAccountAsync);
        }

        /// <summary>
        /// Obtains an <see cref="AccessToken"/> token for a user account silently if the user has already authenticated to another Microsoft application participating in SSO through the MSAL cache
        /// </summary>
        /// <param name="requestContext">The details of the authentication request.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> controlling the request lifetime</param>
        /// <returns>An <see cref="AccessToken"/> which can be used to authenticate service client calls</returns>
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken = default)
        {
            (AccessToken token, Exception ex) = GetTokenImplAsync(requestContext, cancellationToken).GetAwaiter().GetResult();

            if (ex != null)
            {
                if (!(ex is AuthenticationFailedException))
                {
                    ex = new AuthenticationFailedException(Constants.AuthenticationUnhandledExceptionMessage, ex);
                }

                throw ex;
            }

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
            (AccessToken token, Exception ex) = await GetTokenImplAsync(requestContext, cancellationToken).ConfigureAwait(false);

            if (ex != null)
            {
                if (!(ex is AuthenticationFailedException))
                {
                    ex = new AuthenticationFailedException(Constants.AuthenticationUnhandledExceptionMessage, ex);
                }

                throw ex;
            }

            return token;
        }

        (AccessToken, Exception) IExtendedTokenCredential.GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return GetTokenImplAsync(requestContext, cancellationToken).GetAwaiter().GetResult();
        }

        async Task<(AccessToken, Exception)> IExtendedTokenCredential.GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return await GetTokenImplAsync(requestContext, cancellationToken).ConfigureAwait(false);
        }

        private async Task<(AccessToken, Exception)> GetTokenImplAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            IAccount account = null;

            Exception ex = null;

            using CredentialDiagnosticScope scope = _pipeline.StartGetTokenScope("Azure.Identity.SharedTokenCacheCredential.GetToken", requestContext);

            try
            {
                (account, ex) = await _account.Value.ConfigureAwait(false);

                if (account != null)
                {
                    AuthenticationResult result = await _pubApp.AcquireTokenSilent(requestContext.Scopes, account).ExecuteAsync(cancellationToken).ConfigureAwait(false);

                    return (new AccessToken(result.AccessToken, result.ExpiresOn), null);
                }
                else
                {
                    scope.Failed(ex);
                }
            }
            catch (MsalUiRequiredException)
            {
                ex = scope.Failed($"Token aquisition failed for user {_username}. To fix, reauthenticate through tooling supporting azure developer sign on.");
            }
            catch (Exception e)
            {
                ex = scope.Failed(e);
            }

            return (default, ex);
        }

        private async Task<(IAccount, Exception)> GetAccountAsync()
        {
            Exception ex = null;

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
                    ex = new AuthenticationFailedException($"{MultipleAccountsErrorMessage}\n Discovered Accounts: [ {string.Join(", ", accounts.Select(a => a.Username))} ]");
                }
                else
                {
                    ex = new AuthenticationFailedException($"User account '{_username}' was not found in the shared token cache.\n  Discovered Accounts: [ {string.Join(", ", accounts.Select(a => a.Username))} ]");
                }
            }

            return (account, ex);
        }

    }
}
