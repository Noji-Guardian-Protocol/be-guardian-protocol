using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxUpdateComplianceCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckAutomaticUpdates(signals);
            await CheckPendingUpdates(signals);
            await CheckLastUpdate(signals);
            
            return signals;
        }

        private async Task CheckAutomaticUpdates(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("systemctl", "is-enabled unattended-upgrades 2>/dev/null || echo disabled");
                if (output.Trim() == "disabled")
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.AUTOMATED_UPDATE,
                        Security = "UPDATES DISABLED",
                        HipaaViolation = true,
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
                var output = await RunCommandAsync("apt", "list --upgradable 2>/dev/null | wc -l");
                if (int.TryParse(output.Trim(), out var count) && count > 1)
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.AUTOMATED_UPDATE,
                        Security = "CRITICAL PATCH PENDING",
                        VpnConnectionCount = count,
                        HipaaViolation = true,
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckLastUpdate(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("stat", "/var/log/apt/history.log -c %Y");
                if (long.TryParse(output.Trim(), out var lastUpdate))
                {
                    var daysSince = (DateTimeOffset.Now.ToUnixTimeSeconds() - lastUpdate) / 86400;
                    if (daysSince > 30)
                    {
                        signals.Add(new SignalCapture
                        {
                            Type = SignalTypes.AUTOMATED_UPDATE,
                            Security = "DAYS WITHOUT UPDATES",
                            VpnConnectionCount = (int)daysSince,
                            HipaaViolation = true,
                            Timestamp = DateTime.Now
                        });
                    }
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