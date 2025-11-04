using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxSessionTimeoutCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckSessionTimeout(signals);
            
            return signals;
        }

        private async Task CheckSessionTimeout(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("who", "");
                var sessions = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                if (sessions.Length > 1)
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.SESSION_TIMEOUT_SECURITY,
                        Security = "LONG RUNNING SESSION",
                        VpnConnectionCount = sessions.Length,
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