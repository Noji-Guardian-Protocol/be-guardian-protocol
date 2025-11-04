using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using System.Diagnostics;

namespace be_guardianprotocol.Linux
{
    public class LinuxEncryptionCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            var encryptionStatus = await CheckLuksEncryption();
            var tpmStatus = await CheckTpmStatus();
            
            signals.Add(new SignalCapture
            {
                Type = SignalTypes.Encryption,
                EncryptionEnabled = encryptionStatus,
                TmpEnabled = tpmStatus,
                EncryptionMethod = encryptionStatus ? "LUKS" : "None",
                Timestamp = DateTime.Now
            });
            
            return signals;
        }

        private async Task<bool> CheckLuksEncryption()
        {
            try
            {
                var output = await RunCommandAsync("lsblk", "-f | grep crypto_LUKS | wc -l");
                return int.TryParse(output.Trim(), out var count) && count > 0;
            }
            catch { return false; }
        }

        private async Task<bool> CheckTpmStatus()
        {
            try
            {
                var output = await RunCommandAsync("ls", "/dev/tpm* 2>/dev/null | wc -l");
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