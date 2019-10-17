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
        private const int GetTokenFailed = 3;
        private const int GetTokenFailedWithException = 4;
        //private const int RequestContentTextEvent = 17;
        //private const int ResponseEvent = 5;
        //private const int ResponseContentEvent = 6;
        //private const int ResponseDelayEvent = 7;
        //private const int ResponseContentTextEvent = 13;
        //private const int ResponseContentBlockEvent = 11;
        //private const int ResponseContentTextBlockEvent = 15;
        //private const int ErrorResponseEvent = 8;
        //private const int ErrorResponseContentEvent = 9;
        //private const int ErrorResponseContentTextEvent = 14;
        //private const int ErrorResponseContentBlockEvent = 12;
        //private const int ErrorResponseContentTextBlockEvent = 16;
        //private const int RequestRetryingEvent = 10;

        private AzureIdentityEventSource() : base(EventSourceName, EventSourceSettings.Default, AzureEventSourceListener.TraitName, AzureEventSourceListener.TraitValue) { }

        public static AzureIdentityEventSource Singleton { get; } = new AzureIdentityEventSource();

        [Event(GetTokenEvent, Level = EventLevel.Informational, Message = "{0}.GetToken [ Scopes: {1} ParentRequestId: {2} ]")]
        public void CredentialGetToken(string credentialType, TokenRequestContext context)
        {
            WriteEvent(GetTokenEvent, credentialType, context.Scopes, context.ParentRequestId);
        }

        [Event(GetTokenSucceededEvent, Level = EventLevel.Informational, Message = "{0}.GetToken succeeded [ Scopes: {1} ParentRequestId: {2} ExpiresOn: {3} ]")]
        public void CredentialGetTokenSuccess(string credentialType, TokenRequestContext context, DateTimeOffset ExpiresOn)
        {
            WriteEvent(GetTokenSucceededEvent, credentialType, context.Scopes, context.ParentRequestId, ExpiresOn);
        }

        [Event(GetTokenFailed, Level = EventLevel.Warning, Message = "{0}.GetToken was unable to retrieve an access token [ Scopes: {1} ParentRequestId: {2} ]")]
        public void CredentialGetTokenFailed(string credentialType, TokenRequestContext context)
        {
            WriteEvent(GetTokenFailed, credentialType, context.Scopes, context.ParentRequestId);
        }

        [Event(GetTokenFailedWithException, Level = EventLevel.Warning, Message = "{0}.GetToken failed due to an unhandled exception [ Scopes: {1} ParentRequestId: {2} ] \n {3}")]
        public void CredentialGetTokenFailedWithException(string credentialType, TokenRequestContext context, string exStr)
        {
            WriteEvent(GetTokenFailedWithException, credentialType, context.Scopes, context.ParentRequestId, exStr);
        }


        //[Event(RequestContentEvent, Level = EventLevel.Verbose, Message = "Request [{0}] Content {1}")]
        //public void RequestContent(string requestId, byte[] content)
        //{
        //    WriteEvent(RequestContentEvent, requestId, content);
        //}

        //[Event(RequestContentTextEvent, Level = EventLevel.Verbose, Message = "Request [{0}] Content {1}")]
        //public void RequestContentText(string requestId, string content)
        //{
        //    WriteEvent(RequestContentTextEvent, requestId, content);
        //}

        //[Event(ResponseEvent, Level = EventLevel.Informational, Message = "Response [{0}] {1} {2} ({4:00.0}s)\r\n{3}")]
        //public void Response(string requestId, int status, string reasonPhrase, string headers, double seconds)
        //{
        //    WriteEvent(ResponseEvent, requestId, status, reasonPhrase, headers, seconds);
        //}

        //[Event(ResponseContentEvent, Level = EventLevel.Verbose, Message = "Request [{0}] Content {1}")]
        //public void ResponseContent(string requestId, byte[] content)
        //{
        //    WriteEvent(ResponseContentEvent, requestId, content);
        //}

        //[Event(ResponseContentBlockEvent, Level = EventLevel.Verbose, Message = "Request [{0}] content block {1}: {2}")]
        //public void ResponseContentBlock(string requestId, int blockNumber, byte[] content)
        //{
        //    WriteEvent(ResponseContentBlockEvent, requestId, blockNumber, content);
        //}

        //[Event(ResponseContentTextEvent, Level = EventLevel.Verbose, Message = "Request [{0}] content: {1}")]
        //public void ResponseContentText(string requestId, string content)
        //{
        //    WriteEvent(ResponseContentTextEvent, requestId, content);
        //}

        //[Event(ResponseContentTextBlockEvent, Level = EventLevel.Verbose, Message = "Request [{0}] content block {1}: {2}")]
        //public void ResponseContentTextBlock(string requestId, int blockNumber, string content)
        //{
        //    WriteEvent(ResponseContentTextBlockEvent, requestId, blockNumber, content);
        //}

        //[Event(ErrorResponseEvent, Level = EventLevel.Warning, Message = "Error Response [{0}] {1} {2} ({4:00.0}s)\r\n{3}")]
        //public void ErrorResponse(string requestId, int status, string reasonPhrase, string headers, double seconds)
        //{
        //    WriteEvent(ErrorResponseEvent, requestId, status, reasonPhrase, headers, seconds);
        //}

        //[Event(ErrorResponseContentEvent, Level = EventLevel.Informational, Message = "Response [{0}] content: {1}")]
        //public void ErrorResponseContent(string requestId, byte[] content)
        //{
        //    WriteEvent(ErrorResponseContentEvent, requestId, content);
        //}

        //[Event(ErrorResponseContentBlockEvent, Level = EventLevel.Informational, Message = "Request [{0}] content block {1}: {2}")]
        //public void ErrorResponseContentBlock(string requestId, int blockNumber, byte[] content)
        //{
        //    WriteEvent(ErrorResponseContentBlockEvent, requestId, blockNumber, content);
        //}

        //[Event(ErrorResponseContentTextEvent, Level = EventLevel.Informational, Message = "Request [{0}] content: {1}")]
        //public void ErrorResponseContentText(string requestId, string content)
        //{
        //    WriteEvent(ErrorResponseContentTextEvent, requestId, content);
        //}

        //[Event(ErrorResponseContentTextBlockEvent, Level = EventLevel.Informational, Message = "Request [{0}] content block {1}: {2}")]
        //public void ErrorResponseContentTextBlock(string requestId, int blockNumber, string content)
        //{
        //    WriteEvent(ErrorResponseContentTextBlockEvent, requestId, blockNumber, content);
        //}

        //[Event(RequestRetryingEvent, Level = EventLevel.Informational, Message = "Request [{0}] retry number: {1}")]
        //public void RequestRetrying(string requestId, int retryNumber)
        //{
        //    WriteEvent(RequestRetryingEvent, requestId, retryNumber);
        //}

        //[Event(ResponseDelayEvent, Level = EventLevel.Warning, Message = "Request [{0}] took {1:00.0}s")]
        //public void ResponseDelay(string requestId, double seconds)
        //{
        //    WriteEvent(ResponseDelayEvent, requestId, seconds);
        //}
    }
}
