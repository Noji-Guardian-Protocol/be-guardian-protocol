using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacVpnCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            var vpnStatus = await CheckVpnStatus();
            var networkInterfaces = await GetNetworkInterfaces();
            
            signals.Add(new SignalCapture
            {
                Type = SignalTypes.VPN,
                IsConnected = vpnStatus == "Connected",
                VpnConnectionName = "Mac VPN",
                Timestamp = DateTime.Now
            });
            
            return signals;
        }

        private async Task<string> CheckVpnStatus()
        {
            try
            {
                var output = await RunCommandAsync("scutil", "--nc list | grep Connected");
                return string.IsNullOrWhiteSpace(output) ? "Disconnected" : "Connected";
            }
            catch { return "Unknown"; }
        }

        private async Task<string> GetNetworkInterfaces()
        {
            try
            {
                var output = await RunCommandAsync("ifconfig", "| grep 'inet ' | wc -l");
                return output.Trim();
            }
            catch { return "0"; }
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