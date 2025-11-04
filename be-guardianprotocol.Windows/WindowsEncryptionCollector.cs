using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using System.Diagnostics;

namespace be_guardianprotocol.Windows
{
    public class WindowsEncryptionCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;

        public WindowsEncryptionCollector()
        {
            _logger = new NetworkConnectionLogger();
        }

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();

            try
            {
                var encryptionStatus = await GetEncryptionStatusAsync();
                var tpmStatus = await GetTmpStatusAsync();
                
                var capture = new SignalCapture
                {
                    Type = SignalTypes.Encryption,
                    IsConnected = encryptionStatus.IsEncrypted,
                    Timestamp = DateTime.Now,
                    EncryptionEnabled = encryptionStatus.IsEncrypted,
                    EncryptionMethod = encryptionStatus.Method,
                    EncryptionPercentage = encryptionStatus.Percentage,
                    TmpEnabled = tpmStatus.IsEnabled,
                    TmpVersion = tpmStatus.Version,
                    HipaaViolation = !encryptionStatus.IsEncrypted,
                    ComplianceRule = !encryptionStatus.IsEncrypted ? "HIPAA 164.312(a)(2)(iv)" : null,
                    MitreTactic = !encryptionStatus.IsEncrypted ? "Impact" : null,
                    MitreTechnique = !encryptionStatus.IsEncrypted ? "T1486 - Data Encrypted for Impact" : null,
                    ThreatDetected = !encryptionStatus.IsEncrypted ? "AN1360 - Unencrypted Device" : null,
                    EncryptedVolumeCount = encryptionStatus.EncryptedVolumes,
                    UnencryptedVolumeCount = encryptionStatus.UnencryptedVolumes
                };

                await _logger.LogConnectionAsync(capture);
                results.Add(capture);
            }
            catch (Exception ex)
            {
                var errorCapture = new SignalCapture
                {
                    Type = SignalTypes.Encryption,
                    IsConnected = false,
                    Timestamp = DateTime.Now,
                    ErrorMessage = ex.Message
                };
                results.Add(errorCapture);
            }

            return results;
        }

        private async Task<EncryptionStatus> GetEncryptionStatusAsync()
        {
            var status = new EncryptionStatus();

            try
            {
                var bitlockerOutput = await RunCommandAsync("manage-bde", "-status");
                
                if (bitlockerOutput.Contains("Protection On"))
                {
                    status.IsEncrypted = true;
                    status.Method = "BitLocker";
                    status.EncryptedVolumes = 1;
                }
                else
                {
                    status.UnencryptedVolumes = 1;
                }
            }
            catch { /* Silent fail */ }

            return status;
        }

        private async Task<TmpStatus> GetTmpStatusAsync()
        {
            var status = new TmpStatus();

            try
            {
                var tpmOutput = await RunCommandAsync("powershell", "Get-Tpm | Select-Object TmpPresent,TmpReady,TmpEnabled");
                
                if (tpmOutput.Contains("True"))
                {
                    status.IsEnabled = true;
                    status.Version = "2.0";
                }
            }
            catch { /* Silent fail */ }

            return status;
        }

        private async Task<string> RunCommandAsync(string cmd, string args)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = cmd,
                        Arguments = args,
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
            catch
            {
                return "";
            }
        }
    }

    public class EncryptionStatus
    {
        public bool IsEncrypted { get; set; }
        public string Method { get; set; } = "";
        public double Percentage { get; set; } = 100;
        public int EncryptedVolumes { get; set; }
        public int UnencryptedVolumes { get; set; }
    }

    public class TmpStatus
    {
        public bool IsEnabled { get; set; }
        public string Version { get; set; } = "";
    }
}