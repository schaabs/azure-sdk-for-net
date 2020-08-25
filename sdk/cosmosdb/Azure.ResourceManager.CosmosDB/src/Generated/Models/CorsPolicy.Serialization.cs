// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.CosmosDB.Models
{
    public partial class CorsPolicy : IUtf8JsonSerializable
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            writer.WritePropertyName("allowedOrigins");
            writer.WriteStringValue(AllowedOrigins);
            if (Optional.IsDefined(AllowedMethods))
            {
                writer.WritePropertyName("allowedMethods");
                writer.WriteStringValue(AllowedMethods);
            }
            if (Optional.IsDefined(AllowedHeaders))
            {
                writer.WritePropertyName("allowedHeaders");
                writer.WriteStringValue(AllowedHeaders);
            }
            if (Optional.IsDefined(ExposedHeaders))
            {
                writer.WritePropertyName("exposedHeaders");
                writer.WriteStringValue(ExposedHeaders);
            }
            if (Optional.IsDefined(MaxAgeInSeconds))
            {
                writer.WritePropertyName("maxAgeInSeconds");
                writer.WriteNumberValue(MaxAgeInSeconds.Value);
            }
            writer.WriteEndObject();
        }

        internal static CorsPolicy DeserializeCorsPolicy(JsonElement element)
        {
            string allowedOrigins = default;
            Optional<string> allowedMethods = default;
            Optional<string> allowedHeaders = default;
            Optional<string> exposedHeaders = default;
            Optional<long> maxAgeInSeconds = default;
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("allowedOrigins"))
                {
                    allowedOrigins = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("allowedMethods"))
                {
                    allowedMethods = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("allowedHeaders"))
                {
                    allowedHeaders = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("exposedHeaders"))
                {
                    exposedHeaders = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("maxAgeInSeconds"))
                {
                    maxAgeInSeconds = property.Value.GetInt64();
                    continue;
                }
            }
            return new CorsPolicy(allowedOrigins, allowedMethods.Value, allowedHeaders.Value, exposedHeaders.Value, Optional.ToNullable(maxAgeInSeconds));
        }
    }
}
