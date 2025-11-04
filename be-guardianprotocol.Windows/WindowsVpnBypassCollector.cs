using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using System.Diagnostics;
using System.Text.Json;

namespace be_guardianprotocol.Windows
{
    public class WindowsVpnBypassCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;
        private readonly VpnBypassConfig _config;
        private static int _vpnRejectionCount = 0;
        private static DateTime _lastVpnAttempt = DateTime.MinValue;

        public WindowsVpnBypassCollector()
        {
            _logger = new NetworkConnectionLogger();
            _config = LoadConfig();
        }

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();

            try
            {
                var unauthorizedVpns = await DetectUnauthorizedVpnAppsAsync();
                var vpnBypassBehavior = await DetectVpnBypassPatternsAsync();
                var networkConnections = await AnalyzeNetworkConnectionsAsync();

                if (unauthorizedVpns.Any() || vpnBypassBehavior.IsVpnRejection || networkConnections.HasUnauthorizedVpnTraffic)
                {
                    var capture = new SignalCapture
                    {
                        Type = SignalTypes.VPN_BYPASS,
                        IsConnected = unauthorizedVpns.Any(),
                        Timestamp = DateTime.Now,
                        ProcessName = string.Join(",", unauthorizedVpns.Select(v => v.ProcessName)),
                        Security = BuildSecurityMessage(unauthorizedVpns, vpnBypassBehavior, networkConnections),
                        HipaaViolation = true,
                        ComplianceRule = "HIPAA 164.312(e)(1) & 164.312(a)(1)",
                        MitreTactic = "Command & Control, Defense Evasion",
                        MitreTechnique = "T1090 - Proxy, T1573 - Encrypted Channel, T1562 - Impair Defenses",
                        ThreatDetected = "AN1004 - Unauthorized VPN Usage",
                        VpnConnectionCount = _vpnRejectionCount
                    };

                    await _logger.LogConnectionAsync(capture);
                    results.Add(capture);
                }
            }
            catch (Exception ex)
            {
                var errorCapture = new SignalCapture
                {
                    Type = SignalTypes.VPN_BYPASS,
                    IsConnected = false,
                    Timestamp = DateTime.Now,
                    ErrorMessage = ex.Message
                };
                results.Add(errorCapture);
            }

            return results;
        }

        private async Task<List<UnauthorizedVpnApp>> DetectUnauthorizedVpnAppsAsync()
        {
            var unauthorizedApps = new List<UnauthorizedVpnApp>();

            try
            {
                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    try
                    {
                        var processName = process.ProcessName.ToLower();
                        var vpnApp = _config.UnauthorizedVpnApps.FirstOrDefault(app => 
                            processName.Contains(app.ProcessName.ToLower()));

                        if (vpnApp != null)
                        {
                            unauthorizedApps.Add(new UnauthorizedVpnApp
                            {
                                ProcessName = process.ProcessName,
                                ProcessId = process.Id,
                                VpnProvider = vpnApp.Provider,
                                StartTime = process.StartTime
                            });
                        }
                    }
                    catch { /* Skip processes we can't access */ }
                }
            }
            catch { /* Silent fail */ }

            return unauthorizedApps;
        }

        private async Task<VpnBypassBehavior> DetectVpnBypassPatternsAsync()
        {
            var behavior = new VpnBypassBehavior();

            try
            {
                var eventLogs = await GetVpnEventLogsAsync();
                var recentRejections = eventLogs.Count(log => 
                    log.Contains("rejected") || log.Contains("cancelled") || log.Contains("refused"));

                if (recentRejections > _config.VpnRejectionThreshold)
                {
                    _vpnRejectionCount += recentRejections;
                    behavior.IsVpnRejection = true;
                    behavior.RejectionCount = recentRejections;
                    _lastVpnAttempt = DateTime.Now;
                }

                var timeSinceLastAttempt = DateTime.Now - _lastVpnAttempt;
                if (timeSinceLastAttempt.TotalMinutes > _config.VpnAvoidanceTimeWindow)
                {
                    behavior.IsVpnAvoidance = true;
                }
            }
            catch { /* Silent fail */ }

            return behavior;
        }

        private async Task<NetworkConnectionAnalysis> AnalyzeNetworkConnectionsAsync()
        {
            var analysis = new NetworkConnectionAnalysis();

            try
            {
                var netstat = await RunCommandAsync("netstat", "-an");
                var connections = netstat.Split('\n');

                foreach (var connection in connections)
                {
                    if (connection.Contains("ESTABLISHED"))
                    {
                        var parts = connection.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 3)
                        {
                            var remoteEndpoint = parts[2];
                            if (IsKnownVpnProvider(remoteEndpoint))
                            {
                                analysis.HasUnauthorizedVpnTraffic = true;
                                analysis.UnauthorizedConnections.Add(remoteEndpoint);
                            }
                        }
                    }
                }
            }
            catch { /* Silent fail */ }

            return analysis;
        }

        private async Task<List<string>> GetVpnEventLogsAsync()
        {
            var logs = new List<string>();

            try
            {
                var eventLog = await RunCommandAsync("wevtutil", 
                    "qe System /c:50 /f:text /q:\"*[System[Provider[@Name='RasClient']]]\"");
                
                if (!string.IsNullOrEmpty(eventLog))
                {
                    logs.AddRange(eventLog.Split('\n').Where(line => 
                        line.Contains("VPN") || line.Contains("connection")));
                }
            }
            catch { /* Silent fail */ }

            return logs;
        }

        private bool IsKnownVpnProvider(string endpoint)
        {
            var knownProviders = _config.KnownVpnProviderIPs;
            return knownProviders.Any(provider => endpoint.Contains(provider));
        }

        private string BuildSecurityMessage(List<UnauthorizedVpnApp> vpnApps, 
            VpnBypassBehavior behavior, NetworkConnectionAnalysis connections)
        {
            var messages = new List<string>();

            if (vpnApps.Any())
            {
                messages.Add($"UNAUTHORIZED VPN: {string.Join(", ", vpnApps.Select(v => v.VpnProvider))}");
            }

            if (behavior.IsVpnRejection)
            {
                messages.Add($"VPN REJECTION: {behavior.RejectionCount} attempts");
            }

            if (behavior.IsVpnAvoidance)
            {
                messages.Add("VPN AVOIDANCE: Extended period without corporate VPN");
            }

            if (connections.HasUnauthorizedVpnTraffic)
            {
                messages.Add($"UNAUTHORIZED TRAFFIC: {connections.UnauthorizedConnections.Count} connections");
            }

            return string.Join(" | ", messages);
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

        private VpnBypassConfig LoadConfig()
        {
            try
            {
                var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "vpn-bypass-config.json");
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    return JsonSerializer.Deserialize<VpnBypassConfig>(json) ?? new VpnBypassConfig();
                }
            }
            catch { /* Silent fail */ }

            return new VpnBypassConfig();
        }
    }

    public class VpnBypassConfig
    {
        public List<VpnAppDefinition> UnauthorizedVpnApps { get; set; } = new()
        {
            new() { ProcessName = "nordvpn", Provider = "NordVPN" },
            new() { ProcessName = "expressvpn", Provider = "ExpressVPN" },
            new() { ProcessName = "protonvpn", Provider = "ProtonVPN" },
            new() { ProcessName = "surfshark", Provider = "Surfshark" },
            new() { ProcessName = "cyberghost", Provider = "CyberGhost" },
            new() { ProcessName = "tunnelbear", Provider = "TunnelBear" },
            new() { ProcessName = "hotspotshield", Provider = "Hotspot Shield" },
            new() { ProcessName = "privatevpn", Provider = "PrivateVPN" }
        };

        public List<string> KnownVpnProviderIPs { get; set; } = new()
        {
            "nordvpn.com", "expressvpn.com", "protonvpn.com", "surfshark.com"
        };

        public int VpnRejectionThreshold { get; set; } = 3;
        public int VpnAvoidanceTimeWindow { get; set; } = 60; // minutes
    }

    public class VpnAppDefinition
    {
        public string ProcessName { get; set; } = "";
        public string Provider { get; set; } = "";
    }

    public class UnauthorizedVpnApp
    {
        public string ProcessName { get; set; } = "";
        public int ProcessId { get; set; }
        public string VpnProvider { get; set; } = "";
        public DateTime StartTime { get; set; }
    }

    public class VpnBypassBehavior
    {
        public bool IsVpnRejection { get; set; }
        public bool IsVpnAvoidance { get; set; }
        public int RejectionCount { get; set; }
    }

    public class NetworkConnectionAnalysis
    {
        public bool HasUnauthorizedVpnTraffic { get; set; }
        public List<string> UnauthorizedConnections { get; set; } = new();
    }
}