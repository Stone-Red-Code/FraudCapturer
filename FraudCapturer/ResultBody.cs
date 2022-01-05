using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace FraudCapturer;

internal class ResultBody
{
    [JsonPropertyName("match")]
    public bool Match { get; set; }

    [JsonPropertyName("matches")]
    public List<Result>? Matches { get; set; }
}