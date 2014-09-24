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
using Microsoft.Azure.Management.Insights.Models;

namespace Microsoft.Azure.Management.Insights.Models
{
    /// <summary>
    /// represents a windows event log collection configuration.
    /// </summary>
    public partial class WindowsEventLog : BasicConfiguration
    {
        private IList<string> _dataSources;
        
        /// <summary>
        /// Optional. The Windows Event logs to collect. A list of XPath
        /// queries describing the windows events to be collected. For
        /// example: "System!*[System[(Level &lt;=3)]]". To collect all events
        /// specify "*".
        /// </summary>
        public IList<string> DataSources
        {
            get { return this._dataSources; }
            set { this._dataSources = value; }
        }
        
        /// <summary>
        /// Initializes a new instance of the WindowsEventLog class.
        /// </summary>
        public WindowsEventLog()
        {
            this.DataSources = new List<string>();
        }
    }
}
