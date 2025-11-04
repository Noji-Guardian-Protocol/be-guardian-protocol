using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Enums;
using System.Diagnostics;

namespace be_guardianprotocol.Mac
{
    public class MacEncryptionCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            var fileVaultStatus = await CheckFileVault();
            var secureBootStatus = await CheckSecureBoot();
            
            signals.Add(new SignalCapture
            {
                Type = SignalTypes.Encryption,
                Security = $"FileVault: {fileVaultStatus}, SecureBoot: {secureBootStatus}",
                Timestamp = DateTime.Now
            });
            
            return signals;
        }

        private async Task<string> CheckFileVault()
        {
            try
            {
                var output = await RunCommandAsync("fdesetup", "status");
                return output.Contains("On") ? "Enabled" : "Disabled";
            }
            catch { return "Unknown"; }
        }

        private async Task<string> CheckSecureBoot()
        {
            try
            {
                var output = await RunCommandAsync("nvram", "94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy");
                return string.IsNullOrWhiteSpace(output) ? "Disabled" : "Enabled";
            }
            catch { return "Unknown"; }
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