using System.Net;

namespace FraudCapturer;

internal class FirewallHelper
{
    public static void BlockIp(IPAddress? ipAddress)
    {
        if (ipAddress is null)
        {
            throw new ArgumentNullException(nameof(ipAddress));
        }

        AddRuleIfDoesnotExist(ipAddress);

        File.AppendAllText(Program.IpStorePath, $"{Environment.NewLine}{ipAddress}");

        string[] iPs = File.ReadAllLines(Program.IpStorePath);

        System.Diagnostics.Process process = new System.Diagnostics.Process();
        System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo
        {
            WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
            FileName = "cmd.exe",
            Arguments = $"/C netsh advfirewall firewall set rule name=\"{Program.AppName} IP Block\" new remoteIp={string.Join(',', iPs)}"
        };
        process.StartInfo = startInfo;
        _ = process.Start();
    }

    public static void UnblockIp(IPAddress? ipAddress)
    {
        if (ipAddress is null)
        {
            throw new ArgumentNullException(nameof(ipAddress));
        }

        List<string> iPs = File.ReadAllLines(Program.IpStorePath).ToList();
        iPs.Remove(ipAddress.ToString());

        File.WriteAllLines(Program.IpStorePath, iPs);

        System.Diagnostics.Process process = new System.Diagnostics.Process();
        System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo
        {
            WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
            FileName = "cmd.exe",
            Arguments = $"/C netsh advfirewall firewall set rule name=\"{Program.AppName} IP Block\" new remoteIp={string.Join(',', iPs.ToArray())}"
        };
        process.StartInfo = startInfo;
        _ = process.Start();
    }

    public static void AddRuleIfDoesnotExist(IPAddress ipAddress)
    {
        System.Diagnostics.Process process = new System.Diagnostics.Process();
        System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo
        {
            WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
            FileName = "cmd.exe",
            Arguments = $"/C netsh advfirewall firewall show rule name=\"{Program.AppName} IP Block\" >nul || netsh advfirewall firewall add rule name=\"{Program.AppName} IP Block\" dir=in interface=any action=block remoteIp={ipAddress} && netsh advfirewall firewall add rule name=\"{Program.AppName} IP Block\" dir=out interface=any action=block remoteIp={ipAddress}"
        };
        process.StartInfo = startInfo;
        _ = process.Start();
        process.WaitForExit();
    }
}