using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacVpnBypassCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckUnauthorizedVpn(signals);
            await CheckVpnKillSwitch(signals);
            
            return signals;
        }

        private async Task CheckUnauthorizedVpn(List<SignalCapture> signals)
        {
            try
            {
                var vpnApps = new[] { "NordVPN", "ExpressVPN", "Surfshark", "ProtonVPN" };
                foreach (var app in vpnApps)
                {
                    var output = await RunCommandAsync("find", $"/Applications -name '*{app}*' -type d");
                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        signals.Add(new SignalCapture
                        {
                            Type = SignalTypes.VPN_BYPASS,
                            Security = "UNAUTHORIZED VPN",
                            ProcessName = app,
                            HipaaViolation = true,
                            Timestamp = DateTime.Now
                        });
                    }
                }
            }
            catch { }
        }

        private async Task CheckVpnKillSwitch(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("netstat", "-rn | grep default");
                var routes = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                if (routes.Length > 2) // Multiple default routes may indicate VPN bypass
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.VPN_BYPASS,
                        Security = "VPN AVOIDANCE",
                        VpnConnectionCount = routes.Length,
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