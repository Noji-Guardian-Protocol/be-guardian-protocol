using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxScreenLockSecurityCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckScreensaver(signals);
            await CheckIdleTime(signals);
            
            return signals;
        }

        private async Task CheckScreensaver(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("gsettings", "get org.gnome.desktop.screensaver lock-enabled 2>/dev/null || echo false");
                if (output.Trim() == "false")
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
                var output = await RunCommandAsync("xprintidle", "2>/dev/null || echo 0");
                if (long.TryParse(output.Trim(), out var idleMs) && idleMs > 1800000) // 30 minutes
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.SCREEN_LOCK_SECURITY,
                        Security = "EXTENDED IDLE",
                        VpnConnectionCount = (int)(idleMs / 60000),
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