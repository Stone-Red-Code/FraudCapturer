using FraudCapturer.Configuration;
using FraudCapturer.Helpers;

using PacketDotNet;

using SharpPcap;

using Stone_Red_Utilities.ConsoleExtentions;

using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;

namespace FraudCapturer;

public class Program
{
    public const string AppName = "FraudCapturer";
    public const string AppUrl = "https://github.com/Stone-Red-Code/FraudCapturer";
    public const string IpStorePath = "ipAdresses.txt";
    public const string ConfigStorePath = "config.txt";

    private static DateTime lastCacheClear;
    private static string lastDomain = string.Empty;

    private static readonly ConcurrentBag<string> capturedIpsCache = new();
    private static readonly ConcurrentDictionary<string, DomainInfo?> capturedDomainsCache = new();

    private static BlockConfig blockConfig = new BlockConfig();

    /// <summary>
    /// The main entry point for the application.
    /// </summary>
    private static void Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        // Print SharpPcap version
        Console.WriteLine($"{AppName} - {AppUrl}");
        Console.WriteLine();

        // Retrieve the device list
        CaptureDeviceList devices = CaptureDeviceList.Instance;

        if (args.FirstOrDefault() == "config")
        {
            blockConfig = new Configurator().GetConfig();
            string jsonConfig = JsonSerializer.Serialize(blockConfig);
            File.WriteAllText(ConfigStorePath, jsonConfig);

            Console.WriteLine("-- Configuration saved!");
            return;
        }
        else if (string.IsNullOrWhiteSpace(args.FirstOrDefault()))
        {
            ConsoleExt.WriteLine("No proxycheck api key provided! You are limited to 100 IP checks per day. Get one for free at proxycheck.io.", ConsoleColor.Red);
            Console.WriteLine();
        }
        else
        {
            IpHelper.ProxycheckApiKey = args.FirstOrDefault();
        }

        if (File.Exists(ConfigStorePath))
        {
            blockConfig = JsonSerializer.Deserialize<BlockConfig>(File.ReadAllText(ConfigStorePath)) ?? new BlockConfig();
        }

        // If no devices were found print an error
        if (devices.Count < 1)
        {
            Console.WriteLine("No devices were found on this machine");
            return;
        }

        Console.WriteLine("The following devices are available on this machine:");
        Console.WriteLine("----------------------------------------------------");
        Console.WriteLine();

        //Print all available devices
        int i = 0;

        foreach (ILiveDevice dev in devices)
        {
            Console.WriteLine($"{i}) {dev.Description}");
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

        //Register handler function to the 'packet arrival' event
        device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);

        // Open the device for capturing
        device.Open();

        Console.WriteLine();
        Console.WriteLine($"-- Listening on {device.Description}, hit 'Ctrl-C' to exit...");

        // Start capture of packets
        device.Capture();
    }

    private static void Device_OnPacketArrival(object sender, PacketCapture e)
    {
        RawCapture rawPacket = e.GetPacket();
        ProcessRawPacket(rawPacket);
    }

    private static async void ProcessRawPacket(RawCapture rawPacket)
    {
        Packet packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        if (packet is EthernetPacket)
        {
            IPPacket ip = packet.Extract<IPPacket>();
            if (ip != null)
            {
                IPAddress remoteIpAddress;
                string direction;

                //Check if the package is destined for the PC and determine if it goes in or out.
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

                //Clear cache every 10 minutes.
                if (DateTime.Now - lastCacheClear >= new TimeSpan(0, 10, 0))
                {
                    lastCacheClear = DateTime.Now;
                    capturedIpsCache.Clear();
                    capturedDomainsCache.Clear();
                    File.WriteAllText(IpStorePath, string.Empty);
                    ConsoleExt.WriteLine("Cleared cache", ConsoleColor.Gray);
                }

                //Check if a DNS packet contains a "dangerous" domain.
                await CheckDns(packet, remoteIpAddress, direction);

                if (capturedIpsCache.Contains(remoteIpAddress.ToString()))
                {
                    return;
                }

                capturedIpsCache.Add(remoteIpAddress.ToString());

                //Check if ip address is "dangerous" or blocked
                await CheckIpAddress(remoteIpAddress, direction);

                TimeSpan timeRemainingUntilCacheReset = new TimeSpan(0, 10, 0) - (DateTime.Now - lastCacheClear);
                ConsoleExt.WriteLine($"Next cache reset in {timeRemainingUntilCacheReset.Minutes} minute(s) and {timeRemainingUntilCacheReset.Seconds} second(s)", ConsoleColor.Gray);
            }
        }
    }

    private static async Task CheckIpAddress(IPAddress remoteIpAddress, string direction)
    {
        IpInfo? ipInfo = await IpHelper.GetIpReputation(remoteIpAddress);

        if (IpHelper.IsInternalIpAddress(remoteIpAddress.ToString()))
        {
            ConsoleExt.WriteLine($"[{direction}] [Internal] {remoteIpAddress}", ConsoleColor.Cyan);
        }
        else if (ipInfo is not null)
        {
            bool block = false;
            ConsoleColor consoleColor;

            if (ipInfo.Risk >= 67 && blockConfig.CheckIfBlockSet(ipInfo, blockConfig.HighRiskSet))
            {
                FirewallHelper.BlockIp(remoteIpAddress);
                consoleColor = ConsoleColor.Red;
                block = true;
            }
            else if (ipInfo.Risk <= 33 && blockConfig.CheckIfBlockSet(ipInfo, blockConfig.LowRiskSet))
            {
                FirewallHelper.BlockIp(remoteIpAddress);
                consoleColor = ConsoleColor.Yellow;
                block = true;
            }
            else if (blockConfig.CheckIfBlockSet(ipInfo, blockConfig.MeduimRiskSet))
            {
                FirewallHelper.BlockIp(remoteIpAddress);
                consoleColor = ConsoleColor.DarkYellow;
                block = true;
            }
            else
            {
                consoleColor = ConsoleColor.Green;
            }

            ConsoleExt.WriteLine($"[{direction}] [Provider: {ipInfo.Provider}] [Risk: {ipInfo.Risk}] [Proxy: {ipInfo.IsProxy}] [Type: {ipInfo.Type}] [Block: {block}] {remoteIpAddress}", consoleColor);
        }
        else
        {
            ConsoleExt.WriteLine($"[{direction}] [Invalid] {remoteIpAddress}", ConsoleColor.Magenta);
        }
    }

    private static async Task CheckDns(Packet packet, IPAddress remoteIpAddress, string direction)
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
                    domainInfo = await DomainHelper.GetDomainReputation(domain);
                    _ = capturedDomainsCache.TryAdd(domain, domainInfo);
                }

                if (domainInfo is null)
                {
                    if (lastDomain != domain)
                    {
                        lastDomain = domain;
                        ConsoleExt.WriteLine($"[{direction}] [Dns] [Invalid] [Domain: {domain}] {remoteIpAddress}", ConsoleColor.Magenta);
                    }
                    continue;
                }

                if (domainInfo.IsMatch == false)
                {
                    if (lastDomain != domain)
                    {
                        lastDomain = domain;
                        ConsoleExt.WriteLine($"[{direction}] [Dns] [Domain: {domain}] [Type: Undetected] [Block: {block}] {remoteIpAddress}", ConsoleColor.Green);
                    }
                    continue;
                }

                ConsoleColor consoleColor;

                if (domainInfo.TrustRating >= 0.9)
                {
                    FirewallHelper.BlockIp(domainInfo.IpAddress);
                    consoleColor = ConsoleColor.Red;
                    block = true;
                }
                else if (domainInfo.TrustRating >= 0.5)
                {
                    FirewallHelper.BlockIp(domainInfo.IpAddress);
                    consoleColor = ConsoleColor.DarkYellow;
                    block = true;
                }
                else
                {
                    consoleColor = ConsoleColor.Green;
                }

                if (lastDomain != domain)
                {
                    lastDomain = domain;
                    ConsoleExt.WriteLine($"[{direction}] [Dns] [Domain: {domain}] [Type: {domainInfo.Type}] [Source: {domainInfo.Source}] [Source Trust: {domainInfo.TrustRating * 100d}] [Block: {block}] {remoteIpAddress}", consoleColor);
                }

                Console.ResetColor();
            }
        }
    }
}