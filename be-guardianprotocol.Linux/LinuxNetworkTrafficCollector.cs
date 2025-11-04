using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxNetworkTrafficCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            var networkStats = await GetNetworkStats();
            
            signals.Add(new SignalCapture
            {
                Type = SignalTypes.Network,
                BytesReceived = networkStats.received,
                BytesSent = networkStats.sent,
                Timestamp = DateTime.Now
            });
            
            return signals;
        }

        private async Task<(long received, long sent)> GetNetworkStats()
        {
            try
            {
                var output = await RunCommandAsync("cat", "/proc/net/dev | grep eth0 | awk '{print $2,$10}'");
                var parts = output.Trim().Split(' ');
                if (parts.Length >= 2)
                {
                    long.TryParse(parts[0], out var received);
                    long.TryParse(parts[1], out var sent);
                    return (received, sent);
                }
            }
            catch { }
            return (0, 0);
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