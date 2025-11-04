using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;

namespace be_guardianprotocol.Windows
{
    public class WindowsMfaSecurityCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;
        private readonly HashSet<string> _approvedMfaApps;
        private DateTime _lastEventTime = DateTime.MinValue;

        public WindowsMfaSecurityCollector(NetworkConnectionLogger logger)
        {
            _logger = logger;
            _approvedMfaApps = LoadApprovedMfaApps();
        }

        private HashSet<string> LoadApprovedMfaApps()
        {
            try
            {
                var configPath = "mfa_security_config.json";
                if (System.IO.File.Exists(configPath))
                {
                    var json = System.IO.File.ReadAllText(configPath);
                    var config = JsonSerializer.Deserialize<MfaSecurityConfig>(json);
                    return new HashSet<string>(config.ApprovedMfaApps, StringComparer.OrdinalIgnoreCase);
                }
            }
            catch { }
            
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Microsoft.AAD.BrokerPlugin",
                "Microsoft Authenticator",
                "Okta Verify",
                "Duo Mobile",
                "AuthenticatorApp"
            };
        }

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            try
            {
                CheckMfaAuthenticationEvents();
                CheckUnauthorizedMfaApps();
                return new List<SignalCapture>();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"MFA Security Collection Error: {ex.Message}");
                return new List<SignalCapture>();
            }
        }
        
        public void CollectMfaSecurityData()
        {
            try
            {
                CheckMfaAuthenticationEvents();
                CheckUnauthorizedMfaApps();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"MFA Security Collection Error: {ex.Message}");
            }
        }

        private void CheckMfaAuthenticationEvents()
        {
            try
            {
                var query = "*[System[EventID=4624 or EventID=4625 or EventID=4648] and System[TimeCreated[@SystemTime >= '" + 
                           _lastEventTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") + "']]]";
                
                var eventQuery = new EventLogQuery("Security", PathType.LogName, query);
                var eventReader = new EventLogReader(eventQuery);
                
                EventRecord eventRecord;
                var mfaEvents = new List<MfaEvent>();
                
                while ((eventRecord = eventReader.ReadEvent()) != null)
                {
                    var eventData = eventRecord.ToXml();
                    if (eventData.Contains("MFA") || eventData.Contains("Multi-Factor") || 
                        eventData.Contains("Authentication") && eventData.Contains("Prompt"))
                    {
                        var mfaEvent = ParseMfaEvent(eventRecord);
                        if (mfaEvent != null)
                            mfaEvents.Add(mfaEvent);
                    }
                    _lastEventTime = eventRecord.TimeCreated ?? DateTime.Now;
                }

                ProcessMfaEvents(mfaEvents);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"MFA Event Check Error: {ex.Message}");
            }
        }

        private MfaEvent ParseMfaEvent(EventRecord eventRecord)
        {
            try
            {
                var xml = eventRecord.ToXml();
                return new MfaEvent
                {
                    EventId = eventRecord.Id,
                    TimeCreated = eventRecord.TimeCreated ?? DateTime.Now,
                    IsSuccess = eventRecord.Id == 4624,
                    IsMfaPrompt = xml.Contains("MFA") || xml.Contains("Multi-Factor"),
                    SourceIP = ExtractSourceIP(xml),
                    UserName = ExtractUserName(xml)
                };
            }
            catch
            {
                return null;
            }
        }

        private string ExtractSourceIP(string xml)
        {
            var ipStart = xml.IndexOf("<Data Name='IpAddress'>");
            if (ipStart == -1) return "Unknown";
            ipStart += 23;
            var ipEnd = xml.IndexOf("</Data>", ipStart);
            return ipEnd > ipStart ? xml.Substring(ipStart, ipEnd - ipStart) : "Unknown";
        }

        private string ExtractUserName(string xml)
        {
            var userStart = xml.IndexOf("<Data Name='TargetUserName'>");
            if (userStart == -1) return "Unknown";
            userStart += 28;
            var userEnd = xml.IndexOf("</Data>", userStart);
            return userEnd > userStart ? xml.Substring(userStart, userEnd - userStart) : "Unknown";
        }

        private void ProcessMfaEvents(List<MfaEvent> mfaEvents)
        {
            var now = DateTime.Now;
            var recentEvents = mfaEvents.Where(e => (now - e.TimeCreated).TotalMinutes <= 10).ToList();
            
            // MFA Fatigue Detection
            var rapidPrompts = recentEvents.GroupBy(e => e.SourceIP)
                .Where(g => g.Count() >= 5)
                .SelectMany(g => g);
            
            foreach (var fatigueEvent in rapidPrompts)
            {
                LogMfaSecurityEvent("MFA FATIGUE ATTACK", $"Rapid MFA prompts from {fatigueEvent.SourceIP}", 5);
            }

            // Suspicious MFA Rejections
            var rejectedPrompts = recentEvents.Where(e => !e.IsSuccess && e.IsMfaPrompt).ToList();
            if (rejectedPrompts.Any())
            {
                LogMfaSecurityEvent("SUSPICIOUS MFA REJECTED", $"User correctly rejected {rejectedPrompts.Count} suspicious MFA prompts", rejectedPrompts.Count);
            }

            // Off-hours MFA attempts
            var offHoursEvents = recentEvents.Where(e => e.TimeCreated.Hour < 6 || e.TimeCreated.Hour > 22).ToList();
            if (offHoursEvents.Any())
            {
                LogMfaSecurityEvent("OFF HOURS MFA", $"MFA attempts outside business hours", offHoursEvents.Count);
            }
        }

        private void CheckUnauthorizedMfaApps()
        {
            try
            {
                var runningProcesses = System.Diagnostics.Process.GetProcesses();
                var unauthorizedMfaApps = new List<string>();

                foreach (var process in runningProcesses)
                {
                    try
                    {
                        if (IsMfaRelatedProcess(process.ProcessName) && !_approvedMfaApps.Contains(process.ProcessName))
                        {
                            unauthorizedMfaApps.Add(process.ProcessName);
                        }
                    }
                    catch { }
                }

                if (unauthorizedMfaApps.Any())
                {
                    LogMfaSecurityEvent("UNAUTHORIZED MFA APP", $"Detected unauthorized MFA applications: {string.Join(", ", unauthorizedMfaApps)}", unauthorizedMfaApps.Count);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unauthorized MFA App Check Error: {ex.Message}");
            }
        }

        private bool IsMfaRelatedProcess(string processName)
        {
            var mfaKeywords = new[] { "authenticator", "mfa", "2fa", "totp", "auth", "verify", "duo", "okta" };
            return mfaKeywords.Any(keyword => processName.ToLower().Contains(keyword));
        }

        private void LogMfaSecurityEvent(string securityType, string details, int count)
        {
            var signal = new be_guardianprotocol.Core.Models.SignalEventLog
            {
                SignalType = SignalTypes.MFA_SECURITY.ToString(),
                Timestamp = DateTime.Now,
                ProcessName = "MfaSecurityCollector",
                IsConnected = true,
                Security = securityType,
                VpnConnectionCount = count,
                Details = $"{Environment.UserName}@{Environment.MachineName}: {details}"
            };

            _logger.LogSignal(signal);
        }

        private class MfaEvent
        {
            public int? EventId { get; set; }
            public DateTime TimeCreated { get; set; }
            public bool IsSuccess { get; set; }
            public bool IsMfaPrompt { get; set; }
            public string SourceIP { get; set; } = "";
            public string UserName { get; set; } = "";
        }

        private class MfaSecurityConfig
        {
            public string[] ApprovedMfaApps { get; set; } = Array.Empty<string>();
        }
    }
}