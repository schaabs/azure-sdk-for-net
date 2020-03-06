// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.Management.DataFactory.Models
{
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// A copy activity Dynamics CRM source.
    /// </summary>
    public partial class DynamicsCrmSource : CopySource
    {
        /// <summary>
        /// Initializes a new instance of the DynamicsCrmSource class.
        /// </summary>
        public DynamicsCrmSource()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the DynamicsCrmSource class.
        /// </summary>
        /// <param name="additionalProperties">Unmatched properties from the
        /// message are deserialized this collection</param>
        /// <param name="sourceRetryCount">Source retry count. Type: integer
        /// (or Expression with resultType integer).</param>
        /// <param name="sourceRetryWait">Source retry wait. Type: string (or
        /// Expression with resultType string), pattern:
        /// ((\d+)\.)?(\d\d):(60|([0-5][0-9])):(60|([0-5][0-9])).</param>
        /// <param name="maxConcurrentConnections">The maximum concurrent
        /// connection count for the source data store. Type: integer (or
        /// Expression with resultType integer).</param>
        /// <param name="query">FetchXML is a proprietary query language that
        /// is used in Microsoft Dynamics CRM (online &amp; on-premises). Type:
        /// string (or Expression with resultType string).</param>
        /// <param name="additionalColumns">Specifies the additional columns to
        /// be added to source data. Type: array of objects (or Expression with
        /// resultType array of objects).</param>
        public DynamicsCrmSource(IDictionary<string, object> additionalProperties = default(IDictionary<string, object>), object sourceRetryCount = default(object), object sourceRetryWait = default(object), object maxConcurrentConnections = default(object), object query = default(object), IList<AdditionalColumns> additionalColumns = default(IList<AdditionalColumns>))
            : base(additionalProperties, sourceRetryCount, sourceRetryWait, maxConcurrentConnections)
        {
            Query = query;
            AdditionalColumns = additionalColumns;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets fetchXML is a proprietary query language that is used
        /// in Microsoft Dynamics CRM (online &amp;amp; on-premises). Type:
        /// string (or Expression with resultType string).
        /// </summary>
        [JsonProperty(PropertyName = "query")]
        public object Query { get; set; }

        /// <summary>
        /// Gets or sets specifies the additional columns to be added to source
        /// data. Type: array of objects (or Expression with resultType array
        /// of objects).
        /// </summary>
        [JsonProperty(PropertyName = "additionalColumns")]
        public IList<AdditionalColumns> AdditionalColumns { get; set; }

    }
}
