using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Enums;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacUpdateComplianceCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckAutomaticUpdates(signals);
            await CheckPendingUpdates(signals);
            await CheckOutdatedSoftware(signals);
            
            return signals;
        }

        private async Task CheckAutomaticUpdates(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("defaults", "read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled");
                if (output.Trim() == "0")
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.AUTOMATED_UPDATE,
                        Security = "UPDATES DISABLED",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckPendingUpdates(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("softwareupdate", "-l");
                if (output.Contains("Software Update found"))
                {
                    var lines = output.Split('\n').Where(l => l.Contains("recommended")).ToList();
                    foreach (var line in lines)
                    {
                        signals.Add(new SignalCapture
                        {
                            Type = SignalTypes.AUTOMATED_UPDATE,
                            Security = "CRITICAL PATCH PENDING",
                            Timestamp = DateTime.Now
                        });
                    }
                }
            }
            catch { }
        }

        private async Task CheckOutdatedSoftware(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("brew", "outdated 2>/dev/null || echo 'none'");
                if (!output.Contains("none") && !string.IsNullOrWhiteSpace(output))
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.AUTOMATED_UPDATE,
                        Security = "OUTDATED SOFTWARE",
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