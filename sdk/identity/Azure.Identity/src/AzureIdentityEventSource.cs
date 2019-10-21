// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics.Tracing;

namespace Azure.Core.Diagnostics
{
    [EventSource(Name = EventSourceName)]
    internal sealed class AzureIdentityEventSource : EventSource
    {
        private const string EventSourceName = "Azure-Identity";

        private const int GetTokenEvent = 1;
        private const int GetTokenSucceededEvent = 2;
        private const int GetTokenFailedEvent = 3;
        private const int GetTokenFailedWithExceptionEvent = 4;


        private AzureIdentityEventSource() : base(EventSourceName, EventSourceSettings.Default, AzureEventSourceListener.TraitName, AzureEventSourceListener.TraitValue) { }

        public static AzureIdentityEventSource Singleton { get; } = new AzureIdentityEventSource();

        [Event(GetTokenEvent, Level = EventLevel.Informational, Message = "{0} [ Scopes: {1} ParentRequestId: {2} ]")]
        public void GetToken(string fullyQualifiedMethod, TokenRequestContext context)
        {
            WriteEvent(GetTokenEvent, fullyQualifiedMethod, context.Scopes, context.ParentRequestId);
        }

        [Event(GetTokenSucceededEvent, Level = EventLevel.Informational, Message = "{0} succeeded [ Scopes: {1} ParentRequestId: {2} ExpiresOn: {3} ]")]
        public void GetTokenSuccess(string fullyQualifiedMethod, TokenRequestContext context, DateTimeOffset ExpiresOn)
        {
            WriteEvent(GetTokenSucceededEvent, fullyQualifiedMethod, context.Scopes, context.ParentRequestId, ExpiresOn);
        }

        [Event(GetTokenFailedEvent, Level = EventLevel.Warning, Message = "{0} was unable to retrieve an access token [ Scopes: {1} ParentRequestId: {2} ] {3}")]
        public void GetTokenFailed(string fullyQualifiedMethod, TokenRequestContext context, Exception ex)
        {
            WriteEvent(GetTokenFailedEvent, fullyQualifiedMethod, context.Scopes, context.ParentRequestId, ex);
        }

    }
}
