namespace FraudCapturer.Configuration;

internal class BlockConfigSet
{
    public BlockConfigSet(bool blockIfNotProxy, bool blockIfProxy, bool blockIfVpn)
    {
        BlockIfNotProxy = blockIfNotProxy;
        BlockIfProxy = blockIfProxy;
        BlockIfVpn = blockIfVpn;
    }

    public bool BlockIfNotProxy { get; }
    public bool BlockIfProxy { get; }
    public bool BlockIfVpn { get; }
}