using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using System.Diagnostics;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;
using System.Net.NetworkInformation;

namespace be_guardianprotocol.Windows
{
    public class WindowsApplicationSecurityCollector : ISignalCollector
    {
        private static readonly NetworkConnectionLogger _logger = new();
        private static readonly HashSet<string> _monitoredProcesses = new();

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();
            
            // Monitor running processes for unauthorized applications
            var processes = Process.GetProcesses();
            foreach (var process in processes)
            {
                try
                {
                    if (process.HasExited || string.IsNullOrEmpty(process.ProcessName)) continue;
                    
                    var processKey = $"{process.ProcessName}_{process.Id}";
                    if (_monitoredProcesses.Contains(processKey)) continue;
                    
                    _monitoredProcesses.Add(processKey);
                    
                    var isApproved = IsApprovedApplication(process);
                    var isSuspiciousLocation = IsSuspiciousLocation(process);
                    var hasValidSignature = HasValidDigitalSignature(process);
                    var isTorrentRelated = IsTorrentRelated(process);
                    
                    if (!isApproved || isSuspiciousLocation || !hasValidSignature || isTorrentRelated)
                    {
                        var capture = new SignalCapture
                        {
                            Type = SignalTypes.Process,
                            ProcessName = process.ProcessName,
                            ProcessId = process.Id,
                            ProcessPath = GetProcessPath(process),
                            IsConnected = true,
                            HipaaViolation = true,
                            ComplianceRule = "HIPAA 164.308(a)(1) & 164.312(c)(1)",
                            MitreTactic = "Initial Access, Execution",
                            MitreTechnique = "T1204 - User Execution, T1059 - Command and Scripting Interpreter",
                            ThreatDetected = "AN0623 - Unauthorized Application Execution"
                        };
                        
                        if (!isApproved)
                            capture.Security = "🚫 UNAPPROVED APPLICATION";
                        if (isSuspiciousLocation)
                            capture.Security += " - 📁 SUSPICIOUS LOCATION";
                        if (!hasValidSignature)
                            capture.Security += " - ⚠️ UNSIGNED/INVALID SIGNATURE";
                        if (isTorrentRelated)
                        {
                            capture.Security += " - 🏴‍☠️ TORRENT/P2P DETECTED";
                            capture.MitreTechnique += ", T1486 - Data Encrypted for Impact";
                        }
                        
                        await _logger.LogConnectionAsync(capture);
                        results.Add(capture);
                    }
                }
                catch { }
            }
            
            // Monitor network for P2P/torrent traffic
            await MonitorTorrentTraffic(results);
            
            return results;
        }

        private static bool IsApprovedApplication(Process process)
        {
            try
            {
                var config = GetApprovedApplicationsConfig();
                var processName = process.ProcessName.ToLower();
                
                if (config.ApprovedApplications.Any(app => processName.Contains(app.ToLower().Replace(".exe", ""))))
                    return true;
                
                var processPath = GetProcessPath(process);
                if (!string.IsNullOrEmpty(processPath))
                {
                    var cert = GetDigitalSignature(processPath);
                    if (cert != null && config.ApprovedPublishers.Any(pub => 
                        cert.Subject.Contains(pub, StringComparison.OrdinalIgnoreCase)))
                        return true;
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsSuspiciousLocation(Process process)
        {
            try
            {
                var processPath = GetProcessPath(process);
                if (string.IsNullOrEmpty(processPath)) return false;
                
                var config = GetApprovedApplicationsConfig();
                return config.SuspiciousDirectories.Any(dir => 
                    processPath.Contains(dir, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        private static bool HasValidDigitalSignature(Process process)
        {
            try
            {
                var processPath = GetProcessPath(process);
                if (string.IsNullOrEmpty(processPath)) return false;
                
                var cert = GetDigitalSignature(processPath);
                return cert != null && cert.Verify();
            }
            catch
            {
                return false;
            }
        }

        private static bool IsTorrentRelated(Process process)
        {
            var torrentKeywords = new[] { "torrent", "utorrent", "bittorrent", "qbittorrent", "deluge", "transmission" };
            return torrentKeywords.Any(keyword => 
                process.ProcessName.Contains(keyword, StringComparison.OrdinalIgnoreCase));
        }

        private static string GetProcessPath(Process process)
        {
            try
            {
                return process.MainModule?.FileName ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static X509Certificate2? GetDigitalSignature(string filePath)
        {
            try
            {
                return new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
            }
            catch
            {
                return null;
            }
        }

        private static async Task MonitorTorrentTraffic(List<SignalCapture> results)
        {
            try
            {
                var connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                var torrentPorts = new[] { 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889 };
                
                foreach (var conn in connections)
                {
                    if (torrentPorts.Contains(conn.LocalEndPoint.Port) || torrentPorts.Contains(conn.RemoteEndPoint.Port))
                    {
                        var capture = new SignalCapture
                        {
                            Type = SignalTypes.Network,
                            IsConnected = true,
                            Security = "🏴‍☠️ TORRENT TRAFFIC DETECTED",
                            HipaaViolation = true,
                            ComplianceRule = "HIPAA 164.308(a)(1) & 164.312(c)(1)",
                            MitreTactic = "Command and Control",
                            MitreTechnique = "T1071 - Application Layer Protocol",
                            ThreatDetected = "AN0624 - P2P/Torrent Network Activity",
                            RemoteAddress = conn.RemoteEndPoint.Address.ToString(),
                            RemotePort = conn.RemoteEndPoint.Port
                        };
                        
                        await _logger.LogConnectionAsync(capture);
                        results.Add(capture);
                    }
                }
            }
            catch { }
        }

        private static ApprovedApplicationsConfig GetApprovedApplicationsConfig()
        {
            try
            {
                var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "approved-applications.json");
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    return JsonSerializer.Deserialize<ApprovedApplicationsConfig>(json) ?? new();
                }
            }
            catch { }
            
            return new ApprovedApplicationsConfig();
        }

        private class ApprovedApplicationsConfig
        {
            public string[] ApprovedApplications { get; set; } = [];
            public string[] ApprovedPublishers { get; set; } = [];
            public string[] SuspiciousDirectories { get; set; } = [];
        }
    }
}