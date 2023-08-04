using PacketDotNet;

using System.Text;

namespace FraudCapturer.Helpers;

internal static class PackageHelper
{
    public static string GetPayloadAsString(this TransportPacket transportPacket)
    {
        byte[] data = transportPacket.PayloadData;
        StringBuilder bytes = new StringBuilder();
        StringBuilder ascii = new StringBuilder();

        for (int i = 1; i <= data.Length; i++)
        {
            // add the current byte to the bytes hex string
            _ = bytes.Append(data[i - 1].ToString("x").PadLeft(2, '0') + " ");

            // add the current byte to the asciiBytes array for later processing
            if (data[i - 1] is < 0x21 or > 0x7e)
            {
                _ = ascii.Append('.');
            }
            else
            {
                _ = ascii.Append(Encoding.ASCII.GetString(new[] { data[i - 1] }));
            }
        }
        return ascii.ToString().Trim('.');
    }
}