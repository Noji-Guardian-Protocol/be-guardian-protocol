using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxVpnCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            var vpnConnected = await CheckVpnStatus();
            
            signals.Add(new SignalCapture
            {
                Type = SignalTypes.VPN,
                IsConnected = vpnConnected,
                VpnConnectionName = "Linux VPN",
                Timestamp = DateTime.Now
            });
            
            return signals;
        }

        private async Task<bool> CheckVpnStatus()
        {
            try
            {
                var output = await RunCommandAsync("ip", "route | grep tun | wc -l");
                return int.TryParse(output.Trim(), out var count) && count > 0;
            }
            catch { return false; }
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