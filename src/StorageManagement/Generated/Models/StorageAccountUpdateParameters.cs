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

namespace Microsoft.WindowsAzure.Management.Storage.Models
{
    /// <summary>
    /// Parameters supplied to the Update Storage Account operation.
    /// </summary>
    public partial class StorageAccountUpdateParameters
    {
        private string _accountType;
        
        /// <summary>
        /// Optional. Specifies whether the account supports locally-redundant
        /// storage, geo-redundant storage, zone-redundant storage, or read
        /// access geo-redundant storage. Possible values are:'Standard_LRS',
        /// 'Standard_ZRS', 'Standard_GRS', and 'Standard_RAGRS'.
        /// </summary>
        public string AccountType
        {
            get { return this._accountType; }
            set { this._accountType = value; }
        }
        
        private string _description;
        
        /// <summary>
        /// Optional.
        /// </summary>
        public string Description
        {
            get { return this._description; }
            set { this._description = value; }
        }
        
        private IDictionary<string, string> _extendedProperties;
        
        /// <summary>
        /// Optional. Represents the name of an extended storage account
        /// property. Each extended property must have a defined name and a
        /// value. You can have a maximum of 50 extended property name/value
        /// pairs. The maximum length of the Name element is 64 characters,
        /// only alphanumeric characters and underscores are valid in the
        /// Name, and the name must start with a letter. Attempting to use
        /// other characters, starting the Name with a non-letter character,
        /// or entering a name that is identical to that of another extended
        /// property owned by the same storage account will result in a status
        /// code 400 (Bad Request) error. Each extended property value has a
        /// maximum length of 255 characters. You can delete an extended
        /// property by setting the value to NULL.
        /// </summary>
        public IDictionary<string, string> ExtendedProperties
        {
            get { return this._extendedProperties; }
            set { this._extendedProperties = value; }
        }
        
        private string _label;
        
        /// <summary>
        /// Optional. A name for the storage account, base64-encoded. The name
        /// may be up to 100 characters in length. The name can be used
        /// identify the storage account for your tracking purposes.
        /// </summary>
        public string Label
        {
            get { return this._label; }
            set { this._label = value; }
        }
        
        /// <summary>
        /// Initializes a new instance of the StorageAccountUpdateParameters
        /// class.
        /// </summary>
        public StorageAccountUpdateParameters()
        {
            this.ExtendedProperties = new Dictionary<string, string>();
        }
    }
}
