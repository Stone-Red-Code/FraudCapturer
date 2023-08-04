namespace FraudCapturer.Configuration;

internal static class Configurator
{
    public static BlockConfig GetConfig()
    {
        BlockConfig blockConfig = new BlockConfig();

        Console.WriteLine("Configuration:");
        Console.WriteLine();

        Console.WriteLine("High risk rules (>=66%):");
        Console.WriteLine("----------------------------------------------------");
        blockConfig.HighRiskSet = GetBlockConfigSetFromConsole(true, true, true);

        Console.WriteLine("High medium rules (>33% & <66%):");
        Console.WriteLine("----------------------------------------------------");
        blockConfig.MeduimRiskSet = GetBlockConfigSetFromConsole(false, true, true);

        Console.WriteLine("High low rules (<=33%):");
        Console.WriteLine("----------------------------------------------------");
        blockConfig.LowRiskSet = GetBlockConfigSetFromConsole(false, true, false);

        return blockConfig;
    }

    private static BlockConfigSet GetBlockConfigSetFromConsole(bool ifNotProxyDefault, bool ifproxyDefault, bool ifVpnDeault)
    {
        BlockConfigSet blockConfigSet = new BlockConfigSet();
        Console.WriteLine($"Block if no Proxy detected {GetDefaultHintString(ifNotProxyDefault)}:");
        blockConfigSet.BlockIfNotProxy = GetBoolValueFromConsole(ifNotProxyDefault);

        Console.WriteLine($"Block if Proxy detected {GetDefaultHintString(ifproxyDefault)}:");
        blockConfigSet.BlockIfProxy = GetBoolValueFromConsole(ifproxyDefault);

        Console.WriteLine($"Block if VPN detected {GetDefaultHintString(ifVpnDeault)}:");
        blockConfigSet.BlockIfVpn = GetBoolValueFromConsole(ifVpnDeault);

        return blockConfigSet;
    }

    private static bool GetBoolValueFromConsole(bool defaultValue)
    {
        string input = Console.ReadLine() ?? string.Empty;

        if (string.IsNullOrWhiteSpace(input))
        {
            return defaultValue;
        }

        while (input.ToLower() is not "y" and not "n")
        {
            input = Console.ReadLine() ?? string.Empty;
        }

        return input.ToLower() == "y";
    }

    private static string GetDefaultHintString(bool defaultValue)
    {
        return defaultValue ? "[Y/n]" : "[y/N]";
    }
}