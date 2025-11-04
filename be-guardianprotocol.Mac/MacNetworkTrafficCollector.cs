using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Enums;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacNetworkTrafficCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            var networkStats = await GetNetworkStats();
            
            signals.Add(new SignalCapture
            {
                Type = SignalTypes.Network,
                Security = networkStats,
                Timestamp = DateTime.Now
            });
            
            return signals;
        }

        private async Task<string> GetNetworkStats()
        {
            try
            {
                var output = await RunCommandAsync("netstat", "-ib | grep -E 'en[0-9]' | head -1");
                var parts = output.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 10)
                {
                    return $"Bytes In: {parts[6]}, Bytes Out: {parts[9]}";
                }
                return "Network stats unavailable";
            }
            catch (UnauthorizedAccessException) { return "Access denied"; }
            catch (System.ComponentModel.Win32Exception) { return "Process access denied"; }
            catch { return "Network stats error"; }
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