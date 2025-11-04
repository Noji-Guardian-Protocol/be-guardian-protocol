using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxVpnBypassCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckUnauthorizedVpn(signals);
            
            return signals;
        }

        private async Task CheckUnauthorizedVpn(List<SignalCapture> signals)
        {
            try
            {
                var vpnApps = new[] { "nordvpn", "expressvpn", "surfshark", "protonvpn" };
                foreach (var app in vpnApps)
                {
                    var output = await RunCommandAsync("which", app);
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