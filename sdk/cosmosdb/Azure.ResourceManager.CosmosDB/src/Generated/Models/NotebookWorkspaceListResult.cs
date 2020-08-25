// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.Collections.Generic;
using Azure.Core;

namespace Azure.ResourceManager.CosmosDB.Models
{
    /// <summary> A list of notebook workspace resources. </summary>
    public partial class NotebookWorkspaceListResult
    {
        /// <summary> Initializes a new instance of NotebookWorkspaceListResult. </summary>
        internal NotebookWorkspaceListResult()
        {
            Value = new ChangeTrackingList<NotebookWorkspace>();
        }

        /// <summary> Initializes a new instance of NotebookWorkspaceListResult. </summary>
        /// <param name="value"> Array of notebook workspace resources. </param>
        internal NotebookWorkspaceListResult(IReadOnlyList<NotebookWorkspace> value)
        {
            Value = value;
        }

        /// <summary> Array of notebook workspace resources. </summary>
        public IReadOnlyList<NotebookWorkspace> Value { get; }
    }
}
