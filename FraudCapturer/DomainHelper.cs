using PacketDotNet;

using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace FraudCapturer;

internal class DomainHelper
{
    public static string[] GetDomainsFromDnsReqest(TransportPacket transportPacket)
    {
        List<string> domains = new();
        MatchCollection matchCollection = Regex.Matches(transportPacket.GetPayloadAsString().ToLower(), @"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]");
        foreach (Match match in matchCollection)
        {
            domains.Add(match.Value);
        }
        return domains.Distinct().ToArray();
    }

    public static DomainInfo? GetDomainReputation(string domain)
    {
        try
        {
            IPAddress[] addresslist = Dns.GetHostAddresses(domain);
            DomainInfo domainInfo = new DomainInfo
            {
                IpAddress = addresslist[0]
            };

            HttpClient httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("User-Agent", $"{Program.AppName} - (coming soon)");

            AntiFishReqestBody reqestBody = new AntiFishReqestBody()
            {
                Message = domain
            };

            HttpContent httpContent = new StringContent(JsonSerializer.Serialize(reqestBody), Encoding.UTF8, "application/json");

            HttpResponseMessage responseMessage = httpClient.PostAsync("https://anti-fish.bitflow.dev/check", httpContent).GetAwaiter().GetResult(); ;

            string resultString = responseMessage.Content.ReadAsStringAsync().GetAwaiter().GetResult(); ;
            AntiFishResultBody? resultBody = JsonSerializer.Deserialize<AntiFishResultBody>(resultString);

            AntiFishResult? result = resultBody?.Matches?.FirstOrDefault(m => m.Domain == domain);

            if (result is null)
            {
                return domainInfo;
            }

            domainInfo.IsMatch = true;
            domainInfo.TrustRating = result.TrustRating;
            domainInfo.Source = result.Source;
            domainInfo.Type = result.Type;

            return domainInfo;
        }
        catch (SocketException ex)
        {
            Console.WriteLine($"error: {ex.Message} ({domain})");
            return null;
        }
    }

    private class AntiFishReqestBody
    {
        [JsonPropertyName("message")]
        public string? Message { get; set; }
    }

    private class AntiFishResult
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

    private class AntiFishResultBody
    {
        [JsonPropertyName("match")]
        public bool Match { get; set; }

        [JsonPropertyName("matches")]
        public List<AntiFishResult>? Matches { get; set; }
    }
}