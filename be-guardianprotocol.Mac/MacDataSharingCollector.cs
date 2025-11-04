using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Enums;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacDataSharingCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckCloudServices(signals);
            await CheckFileSharing(signals);
            await CheckAirDrop(signals);
            
            return signals;
        }

        private async Task CheckCloudServices(List<SignalCapture> signals)
        {
            try
            {
                var processes = await RunCommandAsync("ps", "aux | grep -E '(Dropbox|Google Drive|OneDrive)' | grep -v grep");
                if (!string.IsNullOrWhiteSpace(processes))
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.UNAUTHORIZED_DATA_SHARING,
                        Security = "UNAUTHORIZED CLOUD UPLOAD",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckFileSharing(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("defaults", "read com.apple.AppleFileServer guestAccess");
                if (output.Trim() == "1")
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.UNAUTHORIZED_DATA_SHARING,
                        Security = "PUBLIC FILE SHARING",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckAirDrop(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("defaults", "read com.apple.sharingd DiscoverableMode");
                if (output.Contains("Everyone"))
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.UNAUTHORIZED_DATA_SHARING,
                        Security = "PUBLIC FILE SHARING",
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