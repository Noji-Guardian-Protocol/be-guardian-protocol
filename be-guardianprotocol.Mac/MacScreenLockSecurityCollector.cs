using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacScreenLockSecurityCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckScreenSaver(signals);
            await CheckIdleTime(signals);
            
            return signals;
        }

        private async Task CheckScreenSaver(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("defaults", "read com.apple.screensaver askForPassword");
                if (output.Trim() == "0")
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.SCREEN_LOCK_SECURITY,
                        Security = "SCREENSAVER DISABLED",
                        HipaaViolation = true,
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckIdleTime(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("ioreg", "-c IOHIDSystem | awk '/HIDIdleTime/ {print $3/1000000000; exit}'");
                if (double.TryParse(output.Trim(), out var idleSeconds) && idleSeconds > 1800) // 30 minutes
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.SCREEN_LOCK_SECURITY,
                        Security = "EXTENDED IDLE",
                        VpnConnectionCount = (int)(idleSeconds / 60),
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