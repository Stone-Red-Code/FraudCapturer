namespace FraudCapturer.Configuration;

internal class BlockConfig
{
    public BlockConfigSet LowRiskSet { get; set; } = new BlockConfigSet(false, true, false);
    public BlockConfigSet MeduimRiskSet { get; set; } = new BlockConfigSet(false, true, true);
    public BlockConfigSet HighRiskSet { get; set; } = new BlockConfigSet(true, true, true);

    public bool CheckIfBlock(IpInfo ipInfo)
    {
        if (ipInfo.Risk <= 33)
        {
            return CheckIfBlockSet(ipInfo, LowRiskSet);
        }
        else if (ipInfo.Risk >= 67)
        {
            return CheckIfBlockSet(ipInfo, HighRiskSet);
        }
        else
        {
            return CheckIfBlockSet(ipInfo, MeduimRiskSet);
        }
    }

    public bool CheckIfBlockSet(IpInfo ipInfo, BlockConfigSet blockConfigSet)
    {
        if (ipInfo.Type == "VPN" && blockConfigSet.BlockIfVpn)
        {
            return true;
        }
        else if (ipInfo.IsProxy && blockConfigSet.BlockIfProxy)
        {
            return true;
        }
        else if (!ipInfo.IsProxy && blockConfigSet.BlockIfNotProxy)
        {
            return true;
        }

        return false;
    }
}