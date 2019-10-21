// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Azure.Core;
using Azure.Core.Diagnostics;
using Azure.Core.Pipeline;
using Microsoft.Identity.Client;

namespace Azure.Identity
{
   internal readonly struct CredentialDiagnosticScope : IDisposable
    {
        private readonly string _name;
        private readonly DiagnosticScope _scope;
        private readonly TokenRequestContext _context;

        public CredentialDiagnosticScope(string name, DiagnosticScope scope, TokenRequestContext context)
        {
            _name = name;

            _scope = scope;

            _context = context;
        }

        public string Name { get; }
        public DiagnosticScope Scope { get; }

        public TokenRequestContext Context { get; }

        public AuthenticationFailedException Failed(string message)
        {
            var exception = new AuthenticationFailedException(message);

            AzureIdentityEventSource.Singleton.GetTokenFailed(Name, Context, exception);

            Scope.Failed(exception);

            return exception;
        }

        public AuthenticationFailedException Failed(Exception ex)
        {
            if (!(ex is AuthenticationFailedException))
            {
                ex = new AuthenticationFailedException(Constants.AuthenticationUnhandledExceptionMessage, ex);
            }

            AzureIdentityEventSource.Singleton.GetTokenFailed(Name, Context, ex);

            Scope.Failed(ex);

            return (AuthenticationFailedException)ex;
        }

        public void Dispose()
        {
            Scope.Dispose();
        }
    }

   internal class CredentialPipeline
    {
        private static readonly Lazy<CredentialPipeline> s_Singleton = new Lazy<CredentialPipeline>(() => new CredentialPipeline(new TokenCredentialOptions()));

        private CredentialPipeline(TokenCredentialOptions options)
        {
            AuthorityHost = options.AuthorityHost;

            Pipeline = HttpPipelineBuilder.Build(options);

            Diagnostics = new ClientDiagnostics(options);
        }

        public static CredentialPipeline GetInstance(TokenCredentialOptions options)
        {
            return (options is null) ? s_Singleton.Value : new CredentialPipeline(options);
        }

        public Uri AuthorityHost { get; }

        public HttpPipeline Pipeline { get; }

        public ClientDiagnostics Diagnostics { get; }

        public IConfidentialClientApplication CreateMsalConfidentialClient(string tenantId, string clientId, string clientSecret)
        {
            return ConfidentialClientApplicationBuilder.Create(clientId).WithHttpClientFactory(new HttpPipelineClientFactory(Pipeline)).WithTenantId(tenantId).WithClientSecret(clientSecret).Build();
        }

        public IPublicClientApplication CreateMsalPublicClient(string clientId, string tenantId = default, string redirectUrl = default)
        {
            PublicClientApplicationBuilder pubAppBuilder = PublicClientApplicationBuilder.Create(clientId).WithHttpClientFactory(new HttpPipelineClientFactory(Pipeline));

            if (!string.IsNullOrEmpty(tenantId))
            {
                pubAppBuilder = pubAppBuilder.WithTenantId(tenantId);
            }

            if (!string.IsNullOrEmpty(redirectUrl))
            {
                pubAppBuilder = pubAppBuilder.WithRedirectUri(redirectUrl);
            }

            return pubAppBuilder.Build();
        }

        public CredentialDiagnosticScope StartGetTokenScope(string fullyQualifiedMethod, TokenRequestContext context)
        {
            AzureIdentityEventSource.Singleton.GetToken(fullyQualifiedMethod, context);

            CredentialDiagnosticScope scope = new CredentialDiagnosticScope(fullyQualifiedMethod, Diagnostics.CreateScope(fullyQualifiedMethod), context);

            scope.Scope.Start();

            return scope;
        }
    }
}
