using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using System.Diagnostics;
using System.Text.Json;
using System.ServiceProcess;
using Microsoft.Win32;

namespace be_guardianprotocol.Windows
{
    public class WindowsEndpointProtectionCollector : ISignalCollector
    {
        private static readonly NetworkConnectionLogger _logger = new();
        private static readonly Dictionary<string, DateTime> _lastServiceStatus = new();

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();
            
            var config = GetEndpointProtectionConfig();
            
            // Monitor security services
            await MonitorSecurityServices(results, config);
            
            // Monitor security processes
            MonitorSecurityProcesses(results, config);
            
            // Check Windows Defender status
            await CheckWindowsDefenderStatus(results);
            
            return results;
        }

        private static async Task MonitorSecurityServices(List<SignalCapture> results, EndpointProtectionConfig config)
        {
            foreach (var serviceName in config.SecurityServices)
            {
                try
                {
                    using var service = new ServiceController(serviceName);
                    var currentStatus = service.Status;
                    var statusChanged = false;
                    
                    if (_lastServiceStatus.ContainsKey(serviceName))
                    {
                        statusChanged = _lastServiceStatus[serviceName] != DateTime.Now.Date && 
                                      currentStatus != ServiceControllerStatus.Running;
                    }
                    
                    _lastServiceStatus[serviceName] = DateTime.Now;
                    
                    if (currentStatus != ServiceControllerStatus.Running || statusChanged)
                    {
                        var capture = new SignalCapture
                        {
                            Type = SignalTypes.Process,
                            ProcessName = serviceName,
                            IsConnected = currentStatus == ServiceControllerStatus.Running,
                            Security = $"🛡️ ENDPOINT PROTECTION: {currentStatus}",
                            HipaaViolation = currentStatus != ServiceControllerStatus.Running,
                            ComplianceRule = "HIPAA 164.308(a)(1) & 164.312(c)(1)",
                            MitreTactic = "Defense Evasion",
                            MitreTechnique = "T1562.001 - Disable or Modify Tools",
                            ThreatDetected = "AN1369 - Security Service Disabled"
                        };
                        
                        if (currentStatus != ServiceControllerStatus.Running)
                        {
                            capture.Security += " - ⚠️ SERVICE STOPPED/DISABLED";
                        }
                        
                        await _logger.LogConnectionAsync(capture);
                        results.Add(capture);
                    }
                }
                catch { }
            }
        }

        private static void MonitorSecurityProcesses(List<SignalCapture> results, EndpointProtectionConfig config)
        {
            var runningProcesses = Process.GetProcesses().Select(p => p.ProcessName.ToLower()).ToHashSet();
            
            foreach (var processName in config.SecurityProcesses)
            {
                if (!runningProcesses.Contains(processName.ToLower()))
                {
                    var capture = new SignalCapture
                    {
                        Type = SignalTypes.Process,
                        ProcessName = processName,
                        IsConnected = false,
                        Security = "🛡️ SECURITY PROCESS TERMINATED",
                        HipaaViolation = true,
                        ComplianceRule = "HIPAA 164.308(a)(1) & 164.312(c)(1)",
                        MitreTactic = "Defense Evasion, Persistence",
                        MitreTechnique = "T1562.001 - Disable or Modify Tools, T1543 - Modify System Process",
                        ThreatDetected = "AN1369 - Security Process Killed"
                    };
                    
                    results.Add(capture);
                }
            }
        }

        private static async Task CheckWindowsDefenderStatus(List<SignalCapture> results)
        {
            try
            {
                // Check Windows Defender real-time protection
                var defenderStatus = await GetWindowsDefenderStatus();
                
                if (!defenderStatus.RealTimeProtectionEnabled || !defenderStatus.AntivirusEnabled)
                {
                    var capture = new SignalCapture
                    {
                        Type = SignalTypes.Process,
                        ProcessName = "Windows Defender",
                        IsConnected = defenderStatus.AntivirusEnabled,
                        Security = "🛡️ WINDOWS DEFENDER DISABLED",
                        HipaaViolation = true,
                        ComplianceRule = "HIPAA 164.308(a)(1) & 164.312(c)(1)",
                        MitreTactic = "Defense Evasion",
                        MitreTechnique = "T1562.001 - Disable or Modify Tools",
                        ThreatDetected = "AN1369 - Windows Defender Disabled",
                        EncryptionEnabled = defenderStatus.RealTimeProtectionEnabled,
                        EncryptionMethod = defenderStatus.AntivirusEnabled ? "Enabled" : "Disabled"
                    };
                    
                    await _logger.LogConnectionAsync(capture);
                    results.Add(capture);
                }
            }
            catch { }
        }

        private static async Task<WindowsDefenderStatus> GetWindowsDefenderStatus()
        {
            var status = new WindowsDefenderStatus();
            
            try
            {
                // Check via PowerShell command
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-Command \"Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled | ConvertTo-Json\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                
                using var process = Process.Start(psi);
                if (process != null)
                {
                    var output = await process.StandardOutput.ReadToEndAsync();
                    await process.WaitForExitAsync();
                    
                    if (!string.IsNullOrEmpty(output))
                    {
                        var defenderInfo = JsonSerializer.Deserialize<WindowsDefenderInfo>(output);
                        if (defenderInfo != null)
                        {
                            status.RealTimeProtectionEnabled = defenderInfo.RealTimeProtectionEnabled;
                            status.AntivirusEnabled = defenderInfo.AntivirusEnabled;
                        }
                    }
                }
            }
            catch
            {
                // Fallback to registry check
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
                    if (key != null)
                    {
                        var disableRealtimeMonitoring = key.GetValue("DisableRealtimeMonitoring");
                        status.RealTimeProtectionEnabled = disableRealtimeMonitoring?.ToString() != "1";
                    }
                }
                catch { }
            }
            
            return status;
        }

        private static EndpointProtectionConfig GetEndpointProtectionConfig()
        {
            try
            {
                var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "endpoint-protection-config.json");
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    return JsonSerializer.Deserialize<EndpointProtectionConfig>(json) ?? new();
                }
            }
            catch { }
            
            return new EndpointProtectionConfig();
        }

        private class EndpointProtectionConfig
        {
            public string[] SecurityServices { get; set; } = ["WinDefend", "MsMpSvc"];
            public string[] SecurityProcesses { get; set; } = ["MsMpEng", "NisSrv"];
            public string[] ProcessNameExclusions { get; set; } = ["svchost", "services"];
        }

        private class WindowsDefenderStatus
        {
            public bool RealTimeProtectionEnabled { get; set; }
            public bool AntivirusEnabled { get; set; } = true;
        }

        private class WindowsDefenderInfo
        {
            public bool RealTimeProtectionEnabled { get; set; }
            public bool AntivirusEnabled { get; set; }
        }
    }
}