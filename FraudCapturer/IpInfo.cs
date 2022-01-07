namespace FraudCapturer;

internal class IpInfo
{
    public bool IsProxy { get; set; }
    public string? Type { get; set; }
    public string? Provider { get; set; }
    public int Risk { get; set; }
}