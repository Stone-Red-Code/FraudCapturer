using System.Net;

namespace FraudCapturer;

internal class DomainInfo
{
    public string? Type { get; set; }
    public string? Source { get; set; }
    public double TrustRating { get; set; }
    public bool IsMatch { get; set; }
    public IPAddress? IpAddress { get; set; }
}