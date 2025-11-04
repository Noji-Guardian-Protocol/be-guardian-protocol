using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Enums;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacCloudStorageCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            await CheckiCloudSync(signals);
            await CheckPersonalCloudApps(signals);
            await CheckCloudStoragePolicy(signals);
            
            return signals;
        }

        private async Task CheckiCloudSync(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("defaults", "read com.apple.bird optimize-storage");
                if (output.Trim() == "1")
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.UNAUTHORIZED_CLOUD_STORAGE,
                        Security = "PERSONAL CLOUD STORAGE",
                        Timestamp = DateTime.Now
                    });
                }
            }
            catch { }
        }

        private async Task CheckPersonalCloudApps(List<SignalCapture> signals)
        {
            try
            {
                var apps = new[] { "Dropbox", "Google Drive", "OneDrive", "Box" };
                foreach (var app in apps)
                {
                    var output = await RunCommandAsync("find", $"/Applications -name '*{app}*' -type d");
                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        signals.Add(new SignalCapture
                        {
                            Type = SignalTypes.UNAUTHORIZED_CLOUD_STORAGE,
                            Security = "UNAPPROVED CLOUD SERVICE",
                            Timestamp = DateTime.Now
                        });
                    }
                }
            }
            catch { }
        }

        private async Task CheckCloudStoragePolicy(List<SignalCapture> signals)
        {
            try
            {
                var output = await RunCommandAsync("ps", "aux | grep -E '(sync|upload)' | grep -v grep | wc -l");
                if (int.TryParse(output.Trim(), out var count) && count > 5)
                {
                    signals.Add(new SignalCapture
                    {
                        Type = SignalTypes.UNAUTHORIZED_CLOUD_STORAGE,
                        Security = "CLOUD STORAGE POLICY VIOLATION",
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