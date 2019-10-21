// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace Azure.Identity
{
    internal class CredentialUnavailableException : AuthenticationFailedException
    {

        /// <summary>
        /// Creates a new CredentialUnavailableException with the specified message.
        /// </summary>
        /// <param name="message">The message describing the authentication failure.</param>
        public CredentialUnavailableException(string message)
            : this(message, null)
        {
        }

        /// <summary>
        /// Creates a new CredentialUnavailableException with the specified message.
        /// </summary>
        /// <param name="message">The message describing the authentication failure.</param>
        /// <param name="innerException">The exception underlying the authentication failure.</param>
        public CredentialUnavailableException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
