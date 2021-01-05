// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core.Diagnostics;

namespace Azure.Core.Pipeline
{
    /// <summary>
    /// A policy that sends an <see cref="AccessToken"/> provided by a <see cref="TokenCredential"/> as an Authentication header.
    /// </summary>
    public class BearerTokenAuthenticationPolicy : HttpPipelinePolicy
    {
        private const string AuthenticationChallengePattern = @"(\w+) ((?:\w+="".*?""(?:, )?)+)(?:, )?";
        private const string ChallengeParameterPattern = @"(?:(\w+)=""([^""]*)"")+";

        private static readonly Regex s_AuthenticationChallengeRegex = new Regex(AuthenticationChallengePattern);
        private static readonly Regex s_ChallengeParameterRegex = new Regex(ChallengeParameterPattern);

        private readonly AccessTokenCache _accessTokenCache;
        private readonly string[] _scopes;
        /// <summary>
        /// Creates a new instance of <see cref="BearerTokenAuthenticationPolicy"/> using provided token credential and scope to authenticate for.
        /// </summary>
        /// <param name="credential">The token credential to use for authentication.</param>
        /// <param name="scope">The scope to authenticate for.</param>
        public BearerTokenAuthenticationPolicy(TokenCredential credential, string scope) : this(credential, new[] { scope }) { }

        /// <summary>
        /// Creates a new instance of <see cref="BearerTokenAuthenticationPolicy"/> using provided token credential and scopes to authenticate for.
        /// </summary>
        /// <param name="credential">The token credential to use for authentication.</param>
        /// <param name="scopes">Scopes to authenticate for.</param>
        public BearerTokenAuthenticationPolicy(TokenCredential credential, IEnumerable<string> scopes)
            : this(credential, scopes, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(30)) { }

        internal BearerTokenAuthenticationPolicy(TokenCredential credential, IEnumerable<string> scopes, TimeSpan tokenRefreshOffset, TimeSpan tokenRefreshRetryDelay) {
            Argument.AssertNotNull(credential, nameof(credential));
            Argument.AssertNotNull(scopes, nameof(scopes));
            _scopes = scopes.ToArray();
            _accessTokenCache = new AccessTokenCache(credential, tokenRefreshOffset, tokenRefreshRetryDelay, scopes.ToArray());
        }

        /// <inheritdoc />
        public override ValueTask ProcessAsync(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline)
        {
            return ProcessAsync(message, pipeline, true);
        }

        /// <inheritdoc />
        public override void Process(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline)
        {
            ProcessAsync(message, pipeline, false).EnsureCompleted();
        }

        /// <summary>
        /// Executed before initially sending the request to authenticate the request.
        /// </summary>
        /// <param name="message">The HttpMessage to be authenticated.</param>
        /// <param name="async">Specifies if the method is being called in an asynchronous context</param>
        protected virtual async Task OnBeforeRequestAsync(HttpMessage message, bool async)
        {
            await AuthenticateRequestAsync(message, new TokenRequestContext(_scopes, message.Request.ClientRequestId), async).ConfigureAwait(false);
        }

        /// <summary>
        /// Executed in the event a 401 response with a WWW-Authenticate authentication challenge header is received after the initial request.
        /// </summary>
        /// <remarks>This implementation handles common authentication challenges such as claims challenges. Service client libraries may derive from this and extend to handle service specific authentication challenges.</remarks>
        /// <param name="message">The HttpMessage to be authenticated.</param>
        /// <param name="async">Specifies if the method is being called in an asynchronous context</param>
        /// <returns>A boolean indicated whether the request should be retried</returns>
        protected virtual async Task<bool> OnChallengeAsync(HttpMessage message, bool async)
        {
            var claimsChallenge = GetClaimsChallenge(message.Response);

            if (claimsChallenge != null)
            {
                await AuthenticateRequestAsync(message, new TokenRequestContext(_scopes, message.Request.ClientRequestId, claimsChallenge), async).ConfigureAwait(false);

                return true;
            }

            return false;
        }

        private async Task AuthenticateRequestAsync(HttpMessage message, TokenRequestContext context, bool async)
        {
            string headerValue = await _accessTokenCache.GetHeaderValueAsync(message, context, async);

            message.Request.SetHeader(HttpHeader.Names.Authorization, headerValue);
        }

        private async ValueTask ProcessAsync(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline, bool async)
        {
            if (message.Request.Uri.Scheme != Uri.UriSchemeHttps)
            {
                throw new InvalidOperationException("Bearer token authentication is not permitted for non TLS protected (https) endpoints.");
            }

            await AuthenticateRequestAsync(message, new TokenRequestContext(_scopes, message.Request.ClientRequestId), async).ConfigureAwait(false);

            if (async)
            {
                await ProcessNextAsync(message, pipeline).ConfigureAwait(false);
            }
            else
            {
                ProcessNext(message, pipeline);
            }

            if (message.Response.Status == 401 && message.Response.Headers.Contains("WWW-Authenticate"))
            {
                if (await OnChallengeAsync(message, async).ConfigureAwait(false))
                {
                    if (async)
                    {
                        await ProcessNextAsync(message, pipeline).ConfigureAwait(false);
                    }
                    else
                    {
                        ProcessNext(message, pipeline);
                    }
                }
            }
        }

        private static string? GetClaimsChallenge(Response response)
        {
            if (response.Status == 401 && response.Headers.TryGetValue("WWW-Authenticate", out string? headerValue))
            {
                foreach (var challenge in ParseChallenges(headerValue))
                {
                    if (string.Equals(challenge.Item1, "Bearer", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (var parameter in ParseChallengeParameters(challenge.Item2))
                        {
                            if (string.Equals(parameter.Item1, "claims", StringComparison.OrdinalIgnoreCase))
                            {
                                // currently we are only handling ARM claims challenges which are always b64url encoded, and must be decoded.
                                // some handling will have to be added if we intend to handle claims challenges from Graph as well since they
                                // are not encoded.
                                return Base64Url.DecodeString(parameter.Item2);
                            }
                        }
                    }
                }
            }

            return null;
        }

        internal static IEnumerable<(string, string)> ParseChallenges(string headerValue)
        {
            var challengeMatches = s_AuthenticationChallengeRegex.Matches(headerValue);

            for (int i = 0; i < challengeMatches.Count; i++)
            {
                yield return (challengeMatches[i].Groups[1].Value, challengeMatches[i].Groups[2].Value);
            }
        }

        internal static IEnumerable<(string, string)> ParseChallengeParameters(string challengeValue)
        {
            var paramMatches = s_ChallengeParameterRegex.Matches(challengeValue);

            for (int i = 0; i < paramMatches.Count; i++)
            {
                yield return (paramMatches[i].Groups[1].Value, paramMatches[i].Groups[2].Value);
            }
        }

        private class AccessTokenCache
        {
            private readonly object _syncObj = new object();
            private readonly TokenCredential _credential;
            private readonly TimeSpan _tokenRefreshOffset;
            private readonly TimeSpan _tokenRefreshRetryDelay;

            private TokenRequestContext? _currentContext;
            private TaskCompletionSource<HeaderValueInfo>? _infoTcs;
            private TaskCompletionSource<HeaderValueInfo>? _backgroundUpdateTcs;
            public AccessTokenCache(TokenCredential credential, TimeSpan tokenRefreshOffset, TimeSpan tokenRefreshRetryDelay, string[] initialScopes)
            {
                _credential = credential;
                _tokenRefreshOffset = tokenRefreshOffset;
                _tokenRefreshRetryDelay = tokenRefreshRetryDelay;
                _currentContext = new TokenRequestContext(initialScopes);
            }

            public async ValueTask<string> GetHeaderValueAsync(HttpMessage message, TokenRequestContext context, bool async)
            {
                bool getTokenFromCredential;
                TaskCompletionSource<HeaderValueInfo> headerValueTcs;
                TaskCompletionSource<HeaderValueInfo>? backgroundUpdateTcs;
                (headerValueTcs, backgroundUpdateTcs, getTokenFromCredential) = GetTaskCompletionSources(context);

                if (getTokenFromCredential)
                {
                    if (backgroundUpdateTcs != null)
                    {
                        HeaderValueInfo info = headerValueTcs.Task.EnsureCompleted();
                        _ = Task.Run(() => GetHeaderValueFromCredentialInBackgroundAsync(backgroundUpdateTcs, info, context, async));
                        return info.HeaderValue;
                    }

                    try
                    {
                        HeaderValueInfo info = await GetHeaderValueFromCredentialAsync(context, async, message.CancellationToken);
                        headerValueTcs.SetResult(info);
                    }
                    catch (OperationCanceledException)
                    {
                        headerValueTcs.SetCanceled();
                        throw;
                    }
                    catch (Exception exception)
                    {
                        headerValueTcs.SetException(exception);
                        throw;
                    }
                }

                var headerValueTask = headerValueTcs.Task;
                if (!headerValueTask.IsCompleted)
                {
                    if (async)
                    {
                        await headerValueTask.AwaitWithCancellation(message.CancellationToken);
                    }
                    else
                    {
                        try
                        {
                            headerValueTask.Wait(message.CancellationToken);
                        }
                        catch (AggregateException) { } // ignore exception here to rethrow it with EnsureCompleted
                    }
                }

                return headerValueTcs.Task.EnsureCompleted().HeaderValue;
            }

            private (TaskCompletionSource<HeaderValueInfo> tcs, TaskCompletionSource<HeaderValueInfo>? backgroundUpdateTcs, bool getTokenFromCredential) GetTaskCompletionSources(TokenRequestContext context)
            {
                lock (_syncObj)
                {
                    // Initial state. GetTaskCompletionSources has been called for the first time
                    if (_infoTcs == null || RequestRequiresNewToken(context))
                    {
                        _currentContext = context;
                        _infoTcs = new TaskCompletionSource<HeaderValueInfo>(TaskCreationOptions.RunContinuationsAsynchronously);
                        _backgroundUpdateTcs = default;
                        return (_infoTcs, _backgroundUpdateTcs, true);
                    }

                    // Getting new access token is in progress, wait for it
                    if (!_infoTcs.Task.IsCompleted)
                    {
                        _backgroundUpdateTcs = default;
                        return (_infoTcs, _backgroundUpdateTcs, false);
                    }

                    DateTimeOffset now = DateTimeOffset.UtcNow;
                    // Access token has been successfully acquired in background and it is not expired yet, use it instead of current one
                    if (_backgroundUpdateTcs != null && _backgroundUpdateTcs.Task.Status == TaskStatus.RanToCompletion && _backgroundUpdateTcs.Task.Result.ExpiresOn > now)
                    {
                        _infoTcs = _backgroundUpdateTcs;
                        _backgroundUpdateTcs = default;
                    }

                    // Attempt to get access token has failed or it has already expired. Need to get a new one
                    if (_infoTcs.Task.Status != TaskStatus.RanToCompletion || now >= _infoTcs.Task.Result.ExpiresOn)
                    {
                        _infoTcs = new TaskCompletionSource<HeaderValueInfo>(TaskCreationOptions.RunContinuationsAsynchronously);
                        return (_infoTcs, default, true);
                    }

                    // Access token is still valid but is about to expire, try to get it in background
                    if (now >= _infoTcs.Task.Result.RefreshOn && _backgroundUpdateTcs == null)
                    {
                        _backgroundUpdateTcs = new TaskCompletionSource<HeaderValueInfo>(TaskCreationOptions.RunContinuationsAsynchronously);
                        return (_infoTcs, _backgroundUpdateTcs, true);
                    }

                    // Access token is valid, use it
                    return (_infoTcs, default, false);
                }
            }

            // must be called under lock (_syncObj)
            private bool RequestRequiresNewToken(TokenRequestContext context)
            {
                if (_currentContext == null)
                {
                    return true;
                }

                if (context.Scopes != null)
                {
                    for (int i = 0; i < context.Scopes.Length; i++)
                    {
                        if (context.Scopes[i] != _currentContext.Value.Scopes?[i])
                        {
                            return true;
                        }
                    }
                }

                if ((context.ClaimsChallenge != null) && (context.ClaimsChallenge != _currentContext.Value.ClaimsChallenge))
                {
                    return true;
                }

                return false;
            }

            private async ValueTask GetHeaderValueFromCredentialInBackgroundAsync(TaskCompletionSource<HeaderValueInfo> backgroundUpdateTcs, HeaderValueInfo info, TokenRequestContext context, bool async)
            {
                var cts = new CancellationTokenSource(_tokenRefreshRetryDelay);
                try
                {
                    HeaderValueInfo newInfo = await GetHeaderValueFromCredentialAsync(context, async, cts.Token);
                    backgroundUpdateTcs.SetResult(newInfo);
                }
                catch (OperationCanceledException oce) when (cts.IsCancellationRequested)
                {
                    backgroundUpdateTcs.SetResult(new HeaderValueInfo(info.HeaderValue, info.ExpiresOn, DateTimeOffset.UtcNow));
                    AzureCoreEventSource.Singleton.BackgroundRefreshFailed(context.ParentRequestId ?? string.Empty, oce.ToString());
                }
                catch (Exception e)
                {
                    backgroundUpdateTcs.SetResult(new HeaderValueInfo(info.HeaderValue, info.ExpiresOn, DateTimeOffset.UtcNow + _tokenRefreshRetryDelay));
                    AzureCoreEventSource.Singleton.BackgroundRefreshFailed(context.ParentRequestId ?? string.Empty, e.ToString());
                }
                finally
                {
                    cts.Dispose();
                }
            }

            private async ValueTask<HeaderValueInfo> GetHeaderValueFromCredentialAsync(TokenRequestContext context, bool async, CancellationToken cancellationToken)
            {
                AccessToken token = async
                    ? await _credential.GetTokenAsync(context, cancellationToken).ConfigureAwait(false)
                    : _credential.GetToken(context, cancellationToken);

                return new HeaderValueInfo("Bearer " + token.Token, token.ExpiresOn, token.ExpiresOn - _tokenRefreshOffset);
            }

            private readonly struct HeaderValueInfo
            {
                public string HeaderValue { get; }
                public DateTimeOffset ExpiresOn { get; }
                public DateTimeOffset RefreshOn { get; }

                public HeaderValueInfo(string headerValue, DateTimeOffset expiresOn, DateTimeOffset refreshOn)
                {
                    HeaderValue = headerValue;
                    ExpiresOn = expiresOn;
                    RefreshOn = refreshOn;
                }
            }
        }
    }
}
