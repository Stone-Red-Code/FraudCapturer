
using PacketDotNet;

using SharpPcap;

using System.Net;

namespace FraudCapturer;

/// <summary>
/// Example showing packet manipulation
/// </summary>
public class Program
{
    public const string AppName = "FraudCapturer";
    public const string IpStorePath = "ipAdresses.txt";

    private static DateTime lastCacheClear;
    private static string lastDomain = string.Empty;

    private static readonly List<string> capturedIpsCache = new();
    private static readonly Dictionary<string, DomainInfo> capturedDomainsCache = new();

    /// <summary>
    /// The main entry point for the application.
    /// </summary>
    private static void Main()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        // Print SharpPcap version
        Console.WriteLine(AppName);
        Console.WriteLine();

        // Retrieve the device list
        CaptureDeviceList devices = CaptureDeviceList.Instance;

        // If no devices were found print an error
        if (devices.Count < 1)
        {
            Console.WriteLine("No devices were found on this machine");
            return;
        }

        Console.WriteLine("The following devices are available on this machine:");
        Console.WriteLine("----------------------------------------------------");
        Console.WriteLine();

        int i = 0;

        // Print out the available devices
        foreach (ILiveDevice dev in devices)
        {
            Console.WriteLine("{0}) {1}", i, dev.Description);
            i++;
        }

        Console.WriteLine();

        int choice = -1;
        while (choice < 0 || choice >= devices.Count)
        {
            Console.Write("-- Please choose a device to capture: ");
            bool valid = int.TryParse(Console.ReadLine(), out choice);

            if (!valid)
            {
                choice = -1;
            }
        }

        ICaptureDevice? device = null;

        device = devices[choice];

        //Register our handler function to the 'packet arrival' event
        device.OnPacketArrival +=
            new PacketArrivalEventHandler(Device_OnPacketArrival);

        // Open the device for capturing
        device.Open();

        Console.WriteLine();
        Console.WriteLine("-- Listening on {0}, hit 'Ctrl-C' to exit...", device.Description);

        // Start capture 'INFINTE' number of packets
        device.Capture();

        // Close the pcap device
        // (Note: this line will never be called since
        //  we're capturing infinite number of packets
        device.Close();
    }

    private static void Device_OnPacketArrival(object sender, PacketCapture e)
    {
        RawCapture rawPacket = e.GetPacket();
        Packet packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        if (packet is EthernetPacket)
        {
            IPPacket ip = packet.Extract<IPPacket>();
            if (ip != null)
            {
                IPAddress remoteIpAddress;
                string direction;

                if (IpHelper.IsLocalIpAddress(ip.SourceAddress.ToString()))
                {
                    remoteIpAddress = ip.DestinationAddress;
                    direction = "Out";
                }
                else if (IpHelper.IsLocalIpAddress(ip.DestinationAddress.ToString()))
                {
                    remoteIpAddress = ip.SourceAddress;
                    direction = "In";
                }
                else
                {
                    return;
                }

                if (DateTime.Now - lastCacheClear >= new TimeSpan(0, 10, 0))
                {
                    lastCacheClear = DateTime.Now;
                    capturedIpsCache.Clear();
                    capturedDomainsCache.Clear();
                    File.WriteAllText(IpStorePath, string.Empty);
                    Console.WriteLine("Cleared cache");
                }

                CheckDns(packet, remoteIpAddress, direction);

                if (capturedIpsCache.Contains(remoteIpAddress.ToString()))
                {
                    return;
                }

                TimeSpan timeRemainingUntilCacheReset = new TimeSpan(0, 10, 0) - (DateTime.Now - lastCacheClear);
                Console.WriteLine($"Next cache reset in {timeRemainingUntilCacheReset.Minutes} minute(s) and {timeRemainingUntilCacheReset.Seconds} second(s)");

                capturedIpsCache.Add(remoteIpAddress.ToString());

                CheckIpAddress(remoteIpAddress, direction);
            }
        }
    }

    private static void CheckIpAddress(IPAddress remoteIpAddress, string direction)
    {
        IpInfo? ipInfo = IpHelper.GetIpReputation(remoteIpAddress);

        if (IpHelper.IsInternalIpAddress(remoteIpAddress.ToString()))
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[{direction}] [Internal] {remoteIpAddress}");
        }
        else if (ipInfo is not null)
        {
            bool block = false;
            if (ipInfo.Risk >= 67)
            {
                FirewallHelper.BlockIp(remoteIpAddress);
                Console.ForegroundColor = ConsoleColor.Red;
                block = true;
            }
            else if (ipInfo.Risk >= 34 && ipInfo.IsProxy)
            {
                FirewallHelper.BlockIp(remoteIpAddress);
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                block = true;
            }
            else if (ipInfo.IsProxy && ipInfo.Type != "VPN")
            {
                FirewallHelper.BlockIp(remoteIpAddress);
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                block = true;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
            }

            Console.WriteLine($"[{direction}] [Provider: {ipInfo.Provider}] [Risk: {ipInfo.Risk}] [Proxy: {ipInfo.IsProxy}] [Type: {ipInfo.Type}] [Block: {block}] {remoteIpAddress}");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine($"[{direction}] [Invalid] {remoteIpAddress}");
        }
        Console.ResetColor();
    }

    private static void CheckDns(Packet packet, IPAddress remoteIpAddress, string direction)
    {
        TransportPacket transportPacket = packet.Extract<TcpPacket>();
        transportPacket ??= packet.Extract<UdpPacket>();

        if (transportPacket != null && transportPacket.DestinationPort == 53)
        {
            string[] domains = DomainHelper.GetDomainsFromDnsReqest(transportPacket);
            foreach (string domain in domains)
            {
                DomainInfo? domainInfo;
                bool block = false;

                if (capturedDomainsCache.ContainsKey(domain))
                {
                    domainInfo = capturedDomainsCache[domain];
                }
                else
                {
                    domainInfo = DomainHelper.GetDomainReputation(domain);
                }

                if (domainInfo is null)
                {
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    if (lastDomain != domain)
                    {
                        lastDomain = domain;
                        Console.WriteLine($"[{direction}] [Dns] [Invalid] [Domain: {domain}] {remoteIpAddress}");
                    }
                    Console.ResetColor();
                    continue;
                }

                if (domainInfo.IsMatch == false)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    if (lastDomain != domain)
                    {
                        lastDomain = domain;
                        Console.WriteLine($"[{direction}] [Dns] [Domain: {domain}] [Type: Undetected] [Block: {block}] {remoteIpAddress}");
                    }
                    Console.ResetColor();
                    continue;
                }

                if (domainInfo.TrustRating >= 0.9)
                {
                    FirewallHelper.BlockIp(domainInfo.IpAddress);
                    Console.ForegroundColor = ConsoleColor.Red;
                    block = true;
                }
                else if (domainInfo.TrustRating >= 0.5)
                {
                    FirewallHelper.BlockIp(domainInfo.IpAddress);
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    block = true;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                }

                if (lastDomain != domain)
                {
                    lastDomain = domain;
                    Console.WriteLine($"[{direction}] [Dns] [Domain: {domain}] [Type: {domainInfo.Type}] [Source: {domainInfo.Source}] [Source Trust: {domainInfo.TrustRating * 100d}] [Block: {block}] {remoteIpAddress}");
                }

                Console.ResetColor();
            }
        }
    }
}