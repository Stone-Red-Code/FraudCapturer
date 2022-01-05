using System.Text.Json.Serialization;

namespace FraudCapturer;

internal class ReqestBody
{
    [JsonPropertyName("message")]
    public string? Message { get; set; }
}