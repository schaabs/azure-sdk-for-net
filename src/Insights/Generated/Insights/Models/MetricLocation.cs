// 
// Copyright (c) Microsoft and contributors.  All rights reserved.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//   http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 
// See the License for the specific language governing permissions and
// limitations under the License.
// 

// Warning: This code was generated by a tool.
// 
// Changes to this file may cause incorrect behavior and will be lost if the
// code is regenerated.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Azure.Insights.Models;

namespace Microsoft.Azure.Insights.Models
{
    /// <summary>
    /// Where the data for this metric is stored.
    /// </summary>
    public partial class MetricLocation
    {
        private string _partitionKey;
        
        /// <summary>
        /// Optional. The partition key inside the tables that contains the
        /// metrics.
        /// </summary>
        public string PartitionKey
        {
            get { return this._partitionKey; }
            set { this._partitionKey = value; }
        }
        
        private string _tableEndpoint;
        
        /// <summary>
        /// Optional. The REST endpoint of the tables that contains the metrics.
        /// </summary>
        public string TableEndpoint
        {
            get { return this._tableEndpoint; }
            set { this._tableEndpoint = value; }
        }
        
        private IList<MetricTableInfo> _tableInfo;
        
        /// <summary>
        /// Optional. The list of tables that contain the metric data.
        /// </summary>
        public IList<MetricTableInfo> TableInfo
        {
            get { return this._tableInfo; }
            set { this._tableInfo = value; }
        }
        
        /// <summary>
        /// Initializes a new instance of the MetricLocation class.
        /// </summary>
        public MetricLocation()
        {
            this.TableInfo = new List<MetricTableInfo>();
        }
    }
}
