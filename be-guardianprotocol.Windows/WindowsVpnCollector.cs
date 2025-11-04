using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using System.Diagnostics;
using System.Net.NetworkInformation;

namespace be_guardianprotocol.Windows
{
    public class WindowsVpnCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;

        public WindowsVpnCollector()
        {
            _logger = new NetworkConnectionLogger();
        }

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();

            try
            {
                var vpnConnections = await GetVpnConnectionsAsync();
                var networkTrust = await AnalyzeNetworkTrustAsync();
                
                var isHipaaViolation = networkTrust.IsUntrusted && !vpnConnections.Any(v => v.IsConnected && v.IsCorporate);
                var isBusinessHours = IsBusinessHours(DateTime.Now);
                
                var capture = new SignalCapture
                {
                    Type = SignalTypes.VPN,
                    IsConnected = vpnConnections.Any(v => v.IsConnected),
                    Timestamp = DateTime.Now,
                    IsUntrustedNetwork = networkTrust.IsUntrusted,
                    NetworkSSID = networkTrust.SSID,
                    CorporateVpnDetected = vpnConnections.Any(v => v.IsConnected && v.IsCorporate),
                    HipaaViolation = isHipaaViolation,
                    ComplianceRule = isHipaaViolation ? "HIPAA 164.312(e)(1)" : null,
                    MitreTactic = networkTrust.IsUntrusted ? "Credential Access" : null,
                    MitreTechnique = networkTrust.IsUntrusted ? "T1040 - Network Sniffing" : null,
                    ThreatDetected = isHipaaViolation ? "AN1004 - Unauthorized External Access" : null,
                    IsBusinessHours = isBusinessHours
                };

                await _logger.LogConnectionAsync(capture);
                results.Add(capture);
            }
            catch (Exception ex)
            {
                var errorCapture = new SignalCapture
                {
                    Type = SignalTypes.VPN,
                    IsConnected = false,
                    Timestamp = DateTime.Now,
                    ErrorMessage = ex.Message
                };
                results.Add(errorCapture);
            }

            return results;
        }

        private async Task<List<VpnConnection>> GetVpnConnectionsAsync()
        {
            var connections = new List<VpnConnection>();

            try
            {
                var adapters = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var adapter in adapters)
                {
                    if (IsVpnAdapter(adapter) && adapter.OperationalStatus == OperationalStatus.Up)
                    {
                        connections.Add(new VpnConnection
                        {
                            Name = adapter.Name,
                            IsConnected = true,
                            IsCorporate = IsCorporateVpn(adapter.Name)
                        });
                    }
                }
            }
            catch { /* Silent fail */ }

            return connections;
        }

        private async Task<NetworkTrust> AnalyzeNetworkTrustAsync()
        {
            var trust = new NetworkTrust { IsUntrusted = false };

            try
            {
                var currentProfile = await RunCommandAsync("netsh", "wlan show profile name=* key=clear");
                
                if (currentProfile.Contains("Authentication") && 
                    (currentProfile.Contains("Open") || currentProfile.Contains("None")))
                {
                    trust.IsUntrusted = true;
                }

                var ssidMatch = System.Text.RegularExpressions.Regex.Match(currentProfile, @"SSID name\s*:\s*""([^""]+)""");
                if (ssidMatch.Success)
                {
                    trust.SSID = ssidMatch.Groups[1].Value;
                    
                    var untrustedNames = new[] { "public", "guest", "free", "open", "hotel", "airport", "cafe" };
                    if (untrustedNames.Any(name => trust.SSID.ToLower().Contains(name)))
                    {
                        trust.IsUntrusted = true;
                    }
                }
            }
            catch { /* Silent fail */ }

            return trust;
        }

        private bool IsVpnAdapter(NetworkInterface adapter)
        {
            var vpnTypes = new[] { "vpn", "tunnel", "tap", "tun", "cisco", "fortinet" };
            var name = adapter.Name.ToLower();
            var description = adapter.Description.ToLower();
            
            return vpnTypes.Any(type => name.Contains(type) || description.Contains(type)) ||
                   adapter.NetworkInterfaceType == NetworkInterfaceType.Ppp;
        }

        private bool IsCorporateVpn(string name)
        {
            var corporateKeywords = new[] { "corp", "company", "enterprise", "work", "office" };
            return corporateKeywords.Any(keyword => name.ToLower().Contains(keyword));
        }

        private bool IsBusinessHours(DateTime time)
        {
            var hour = time.Hour;
            return hour >= 8 && hour <= 18 && time.DayOfWeek != DayOfWeek.Saturday && time.DayOfWeek != DayOfWeek.Sunday;
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

    public class VpnConnection
    {
        public string Name { get; set; } = "";
        public bool IsConnected { get; set; }
        public bool IsCorporate { get; set; }
    }

    public class NetworkTrust
    {
        public bool IsUntrusted { get; set; }
        public string SSID { get; set; } = "";
    }
}