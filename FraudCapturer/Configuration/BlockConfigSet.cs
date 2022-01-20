namespace FraudCapturer.Configuration;

internal class BlockConfigSet
{
    public BlockConfigSet(bool blockIfNotProxy, bool blockIfProxy, bool blockIfVpn)
    {
        BlockIfNotProxy = blockIfNotProxy;
        BlockIfProxy = blockIfProxy;
        BlockIfVpn = blockIfVpn;
    }

    public BlockConfigSet()
    {
    }

    public bool BlockIfNotProxy { get; set; }
    public bool BlockIfProxy { get; set; }
    public bool BlockIfVpn { get; set; }
}