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
    public class WindowsPasswordExpirationCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;
        private readonly PasswordExpirationConfig _config;
        private DateTime _lastEventTime = DateTime.MinValue;

        public WindowsPasswordExpirationCollector(NetworkConnectionLogger logger)
        {
            _logger = logger;
            _config = LoadPasswordExpirationConfig();
        }

        private PasswordExpirationConfig LoadPasswordExpirationConfig()
        {
            try
            {
                var configPath = "password_expiration_config.json";
                if (System.IO.File.Exists(configPath))
                {
                    var json = System.IO.File.ReadAllText(configPath);
                    return JsonSerializer.Deserialize<PasswordExpirationConfig>(json) ?? new PasswordExpirationConfig();
                }
            }
            catch { }
            
            return new PasswordExpirationConfig();
        }

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            try
            {
                CheckPasswordExpiration();
                CheckPasswordChangeEvents();
                return new List<SignalCapture>();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Password Expiration Collection Error: {ex.Message}");
                return new List<SignalCapture>();
            }
        }

        public void CollectPasswordExpirationData()
        {
            try
            {
                CheckPasswordExpiration();
                CheckPasswordChangeEvents();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Password Expiration Collection Error: {ex.Message}");
            }
        }

        private void CheckPasswordExpiration()
        {
            try
            {
                var currentUser = Environment.UserName;
                var lastPasswordChange = GetLastPasswordChangeDate(currentUser);
                
                if (lastPasswordChange.HasValue)
                {
                    var daysSinceChange = (DateTime.Now - lastPasswordChange.Value).Days;
                    var isExpired = daysSinceChange > _config.MaxPasswordAgeDays;
                    var isOverdue = daysSinceChange > (_config.MaxPasswordAgeDays - _config.WarningDays);

                    if (isExpired)
                    {
                        LogPasswordExpirationEvent("PASSWORD EXPIRED", $"Password expired {daysSinceChange} days ago", daysSinceChange);
                    }
                    else if (isOverdue)
                    {
                        LogPasswordExpirationEvent("PASSWORD EXPIRATION WARNING", $"Password expires in {_config.MaxPasswordAgeDays - daysSinceChange} days", daysSinceChange);
                    }

                    LogPasswordExpirationEvent("PASSWORD AGE CHECK", $"Password is {daysSinceChange} days old", daysSinceChange);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Password Expiration Check Error: {ex.Message}");
            }
        }

        private void CheckPasswordChangeEvents()
        {
            try
            {
                var query = "*[System[EventID=4723 or EventID=4724] and System[TimeCreated[@SystemTime >= '" + 
                           _lastEventTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") + "']]]";
                
                var eventQuery = new EventLogQuery("Security", PathType.LogName, query);
                var eventReader = new EventLogReader(eventQuery);
                
                EventRecord eventRecord;
                while ((eventRecord = eventReader.ReadEvent()) != null)
                {
                    ProcessPasswordChangeEvent(eventRecord);
                    _lastEventTime = eventRecord.TimeCreated ?? DateTime.Now;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Password Change Event Check Error: {ex.Message}");
            }
        }

        private void ProcessPasswordChangeEvent(EventRecord eventRecord)
        {
            try
            {
                var eventData = eventRecord.ToXml();
                var userName = ExtractUserName(eventData);
                var eventType = eventRecord.Id == 4723 ? "PASSWORD CHANGE ATTEMPT" : "PASSWORD RESET";
                
                LogPasswordExpirationEvent(eventType, $"User {userName} password change detected", 0);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Password Change Event Processing Error: {ex.Message}");
            }
        }

        private DateTime? GetLastPasswordChangeDate(string userName)
        {
            try
            {
                var query = "*[System[EventID=4723 or EventID=4724] and EventData[Data[@Name='TargetUserName']='" + userName + "']]";
                var eventQuery = new EventLogQuery("Security", PathType.LogName, query);
                var eventReader = new EventLogReader(eventQuery);
                
                var latestEvent = eventReader.ReadEvent();
                if (latestEvent != null)
                {
                    return latestEvent.TimeCreated;
                }
            }
            catch { }
            
            // Default to 90 days ago if no password change events found
            return DateTime.Now.AddDays(-90);
        }

        private string ExtractUserName(string xml)
        {
            var userStart = xml.IndexOf("<Data Name='TargetUserName'>");
            if (userStart == -1) return "Unknown";
            userStart += 28;
            var userEnd = xml.IndexOf("</Data>", userStart);
            return userEnd > userStart ? xml.Substring(userStart, userEnd - userStart) : "Unknown";
        }

        private void LogPasswordExpirationEvent(string securityType, string details, int daysSinceChange)
        {
            var signal = new be_guardianprotocol.Core.Models.SignalEventLog
            {
                SignalType = SignalTypes.PASSWORD_EXPIRATION.ToString(),
                Timestamp = DateTime.Now,
                ProcessName = "PasswordExpirationCollector",
                IsConnected = true,
                Security = securityType,
                VpnConnectionCount = daysSinceChange,
                Details = $"{Environment.UserName}@{Environment.MachineName}: {details}"
            };

            _logger.LogSignal(signal);
        }

        private class PasswordExpirationConfig
        {
            public int MaxPasswordAgeDays { get; set; } = 90;
            public int WarningDays { get; set; } = 14;
            public bool EnforceExpiration { get; set; } = true;
        }
    }
}