using System.Text.Json.Serialization;

namespace FraudCapturer;

internal class Result
{
    [JsonPropertyName("followed")]
    public bool Followed { get; set; }

    [JsonPropertyName("domain")]
    public string? Domain { get; set; }

    [JsonPropertyName("source")]
    public string? Source { get; set; }

    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("trust_rating")]
    public double TrustRating { get; set; }
}