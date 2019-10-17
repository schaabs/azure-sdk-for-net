using System;
using System.Collections.Generic;
using System.Text;
using Azure.Core;

namespace Azure.Identity
{
    internal readonly struct ExtendedTokenRequestContext
    {
        public ExtendedTokenRequestContext(TokenRequestContext context, IList<string> errors = default)
        {
            Context = context;

            Errors = errors ?? new List<string>();
        }

        public TokenRequestContext Context { get; }

        public IList<string> Errors { get; }
    }
}
