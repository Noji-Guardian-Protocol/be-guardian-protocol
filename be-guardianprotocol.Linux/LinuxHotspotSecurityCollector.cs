using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxHotspotSecurityCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckHotspot(signals);
            
            return signals;
        }

        private async Task CheckHotspot(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("nmcli", "connection show --active | grep wifi | grep hotspot | wc -l");
                if (int.TryParse(output.Trim(), out var count) && count > 0)
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.HOTSPOT_SECURITY,
                        Security = "INTERNET CONNECTION SHARING",
                        HipaaViolation = true,
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task<string> RunCommandAsync(string command, string args)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"{command} {args}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            return output;
        }
    }
}