using PacketDotNet;

using System.Text;

namespace FraudCapturer.Helpers;

internal static class PackageHelper
{
    public static string GetPayloadAsString(this TransportPacket transportPacket)
    {
        byte[] data = transportPacket.PayloadData;
        string bytes = "";
        string ascii = "";

        for (int i = 1; i <= data.Length; i++)
        {
            // add the current byte to the bytes hex string
            bytes += data[i - 1].ToString("x").PadLeft(2, '0') + " ";

            // add the current byte to the asciiBytes array for later processing
            if (data[i - 1] < 0x21 || data[i - 1] > 0x7e)
            {
                ascii += ".";
            }
            else
            {
                ascii += Encoding.ASCII.GetString(new[] { data[i - 1] });
            }
        }
        return ascii.Trim('.');
    }
}