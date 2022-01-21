using Stone_Red_Utilities.ConsoleExtentions;

using System.Net;
using System.Text.Json;

namespace FraudCapturer.Helpers;

internal class IpHelper
{
    public static string? ProxycheckApiKey { get; set; }

    public static async Task<IpInfo?> GetIpReputation(IPAddress ipAddress)
    {
        HttpClient httpClient = new HttpClient();
        string rawResponseData;

        try
        {
            rawResponseData = await httpClient.GetStringAsync($"http://proxycheck.io/v2/{ipAddress}?key={ProxycheckApiKey}&risk=2&vpn=1&asn=1&tag={Program.AppName}({Environment.MachineName})");
        }
        catch (HttpRequestException ex)
        {
            ConsoleExt.WriteLine($"error: {ex.Message}", ConsoleColor.Gray);
            return null;
        }

        JsonDocument responseData = JsonDocument.Parse(rawResponseData);

        if (!responseData.RootElement.TryGetProperty("status", out JsonElement statusValue))
        {
            return null;
        }

        if (statusValue.GetString() != "ok")
        {
            ConsoleExt.Write(statusValue.GetString(), ConsoleColor.Gray);
            if (responseData.RootElement.TryGetProperty("message", out JsonElement messageValue))
            {
                ConsoleExt.WriteLine($": {messageValue.GetString()}", ConsoleColor.Gray);
            }
            else
            {
                Console.WriteLine();
            }
        }

        if (!responseData.RootElement.TryGetProperty(ipAddress.ToString(), out JsonElement jsonElement))
        {
            return null;
        }

        string type = string.Empty;
        string provider = string.Empty;
        bool isProxy = false;
        int risk = 0;

        if (jsonElement.TryGetProperty("type", out JsonElement typeValue))
        {
            type = typeValue.ToString();
        }

        if (jsonElement.TryGetProperty("provider", out JsonElement providerValue))
        {
            provider = providerValue.ToString();
        }

        if (jsonElement.TryGetProperty("proxy", out JsonElement proxyValue))
        {
            isProxy = proxyValue.GetString() == "yes";
        }

        if (jsonElement.TryGetProperty("risk", out JsonElement riskValue))
        {
            risk = riskValue.GetInt32();
        }

        if (string.IsNullOrWhiteSpace(provider))
        {
            provider = "Unknown";
        }

        IpInfo ipInfo = new IpInfo()
        {
            Type = type,
            IsProxy = isProxy,
            Provider = provider,
            Risk = risk
        };

        return ipInfo;
    }

    public static bool IsInternalIpAddress(string ipAdress)
    {
        if (ipAdress == "::1")
        {
            return true;
        }

        byte[] ip = IPAddress.Parse(ipAdress).GetAddressBytes();
        return ip[0] switch
        {
            10 or 127 => true,
            172 => ip[1] >= 16 && ip[1] < 32,
            192 => ip[1] == 168,
            _ => false,
        };
    }

    public static bool IsLocalIpAddress(string host)
    {
        try
        {
            // get host IP addresses
            IPAddress[] hostIPs = Dns.GetHostAddresses(host);
            // get local IP addresses
            IPAddress[] localIPs = Dns.GetHostAddresses(Dns.GetHostName());

            // test if any host IP equals to any local IP or to localhost
            foreach (IPAddress hostIP in hostIPs)
            {
                if (IPAddress.IsLoopback(hostIP))
                {
                    return true;
                }

                foreach (IPAddress localIP in localIPs)
                {
                    if (hostIP.Equals(localIP))
                    {
                        return true;
                    }
                }
            }
        }
        catch { }
        return false;
    }
}