using IronOcr;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FraudCapturer;

internal class MainWindowViewModel
{
    private readonly Dictionary<string, Result> domainCache = new();

    public MainWindowViewModel()
    {
        Run();
    }

    private Task Run()
    {
        return Task.Run(async () =>
        {
            Dictionary<string, Result> results = await ProcessScreenshot();

            if (results.Count == 0)
            {
                return;
            }
            else
            {
                string alarmText = string.Empty;

                foreach (Result result in results.Values)
                {
                    alarmText += Environment.NewLine;
                    alarmText += $"{Environment.NewLine}Domain: {result.Domain}";
                    alarmText += $"{Environment.NewLine}Type: {result.Type}";
                    alarmText += $"{Environment.NewLine}TrustRating: {result.TrustRating}";
                    alarmText += $"{Environment.NewLine}Followed: {result.Followed}";
                    alarmText += $"{Environment.NewLine}Source: {result.Source}";
                }

                MessageBox.Show(alarmText.Trim(), "Alarm!", MessageBoxButtons.OK, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly);
            }
        }).ContinueWith(t => Run());
    }

    private int count = 0;

    private async Task<Dictionary<string, Result>> ProcessScreenshot()
    {
        count++;
        Debug.WriteLine(count);

        Rectangle rect = new Rectangle(Cursor.Position.X - 300, Cursor.Position.Y - 300, 600, 600);
        Bitmap bitmap = new Bitmap(rect.Width, rect.Height, PixelFormat.Format32bppArgb);
        Graphics g = Graphics.FromImage(bitmap);
        g.CopyFromScreen(rect.Left, rect.Top, 0, 0, bitmap.Size, CopyPixelOperation.SourceCopy);

        string resultText;

        IronTesseract? ocr = new IronTesseract();

        using OcrInput? input = new OcrInput(bitmap);

        // Fast Dictionary
        ocr.Language = OcrLanguage.EnglishFast;

        // Latest Engine
        ocr.Configuration.TesseractVersion = TesseractVersion.Tesseract5;

        //AI OCR only without font analysis
        ocr.Configuration.EngineMode = TesseractEngineMode.LstmOnly;

        //Turn off unneeded options
        ocr.Configuration.ReadBarCodes = false;
        ocr.Configuration.RenderSearchablePdfsAndHocr = false;

        // Assume text is laid out neatly in an orthagonal document
        ocr.Configuration.PageSegmentationMode = TesseractPageSegmentationMode.SparseText;

        OcrResult? result = ocr.Read(input);
        resultText = result.Text;
        Debug.WriteLine(resultText);
        return await ProcessMatches(resultText);
    }

    private async Task<Dictionary<string, Result>> ProcessMatches(string text)
    {
        string newDomains = string.Empty;
        Dictionary<string, Result> results = new();
        MatchCollection matchCollection = Regex.Matches(text.ToLower(), @"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]");

        foreach (Match match in matchCollection)
        {
            if (domainCache.ContainsKey(match.Value))
            {
                results.Add(match.Value, domainCache[match.Value]);
                continue;
            }

            newDomains += $"{match.Value} ";
        }
        if (!string.IsNullOrWhiteSpace(newDomains))
        {
            HttpClient httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Add("User-Agent", "FraudCapturer - (coming soon)");

            ReqestBody reqestBody = new ReqestBody()
            {
                Message = newDomains
            };

            HttpContent httpContent = new StringContent(JsonSerializer.Serialize(reqestBody), Encoding.UTF8, "application/json");

            HttpResponseMessage responseMessage = await httpClient.PostAsync("https://anti-fish.bitflow.dev/check", httpContent);

            string resultString = await responseMessage.Content.ReadAsStringAsync();
            ResultBody? resultBody = JsonSerializer.Deserialize<ResultBody>(resultString);

            if (resultBody is null || resultBody.Matches is null || resultBody.Match == false)
            {
                return results;
            }

            foreach (Result result in resultBody.Matches)
            {
                if (result?.Domain is null)
                {
                    continue;
                }

                domainCache.Add(result.Domain, result);
                results.Add(result.Domain, result);
            }
        }

        return results;
    }
}