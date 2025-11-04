using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacHotspotSecurityCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckInternetSharing(signals);
            
            return signals;
        }

        private async Task CheckInternetSharing(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("defaults", "read /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict 2>/dev/null");
                if (!string.IsNullOrWhiteSpace(output))
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