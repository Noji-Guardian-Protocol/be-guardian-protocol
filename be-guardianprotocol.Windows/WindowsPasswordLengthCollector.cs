using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;

namespace be_guardianprotocol.Windows
{
    public class WindowsPasswordLengthCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;
        private const int REQUIRED_MIN_LENGTH = 20;
        private const int REQUIRED_MAX_LENGTH = 28;

        public WindowsPasswordLengthCollector(NetworkConnectionLogger logger)
        {
            _logger = logger;
        }

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            CheckPasswordPolicyCompliance();
            MonitorPasswordEvents();
            return new[] { new SignalCapture { Type = SignalTypes.PASSWORD_LENGTH_SECURITY } };
        }

        public async Task<SignalCapture> CollectSignalAsync()
        {
            CheckPasswordPolicyCompliance();
            MonitorPasswordEvents();
            return new SignalCapture { Type = SignalTypes.PASSWORD_LENGTH_SECURITY };
        }

        private void CheckPasswordPolicyCompliance()
        {
            try
            {
                // Check Local Security Policy
                var minLength = GetMinimumPasswordLength();
                if (minLength < REQUIRED_MIN_LENGTH)
                {
                    LogPasswordLengthViolation("POLICY VIOLATION", 
                        $"Minimum password length {minLength} is below required {REQUIRED_MIN_LENGTH} characters", 
                        minLength, true);
                }

                // Check Group Policy settings
                CheckGroupPolicyCompliance();
            }
            catch (Exception ex)
            {
                LogPasswordLengthViolation("ERROR", $"Failed to check password policy: {ex.Message}", 0, false);
            }
        }

        private int GetMinimumPasswordLength()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters");
                var value = key?.GetValue("RequireSignOrSeal");
                
                // Check LSA policy
                using var lsaKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
                var minLengthValue = lsaKey?.GetValue("MinimumPasswordLength");
                
                if (minLengthValue != null && int.TryParse(minLengthValue.ToString(), out var length))
                    return length;
                    
                return 0; // Default if not set
            }
            catch
            {
                return 0;
            }
        }

        private void CheckGroupPolicyCompliance()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                var passwordComplexity = key?.GetValue("PasswordComplexity");
                var minPasswordLength = key?.GetValue("MinimumPasswordLength");

                if (minPasswordLength != null && int.TryParse(minPasswordLength.ToString(), out var gpLength))
                {
                    if (gpLength < REQUIRED_MIN_LENGTH)
                    {
                        LogPasswordLengthViolation("GROUP POLICY VIOLATION",
                            $"Group Policy minimum password length {gpLength} is below required {REQUIRED_MIN_LENGTH} characters",
                            gpLength, true);
                    }
                }
            }
            catch { }
        }

        private void MonitorPasswordEvents()
        {
            try
            {
                var query = "*[System[EventID=4723 or EventID=4724 or EventID=4625]]";
                var eventLog = new EventLogQuery("Security", PathType.LogName, query);
                using var reader = new EventLogReader(eventLog);

                EventRecord eventRecord;
                var recentEvents = new List<EventRecord>();
                
                while ((eventRecord = reader.ReadEvent()) != null)
                {
                    if (eventRecord.TimeCreated.HasValue && 
                        eventRecord.TimeCreated.Value > DateTime.Now.AddMinutes(-5))
                    {
                        recentEvents.Add(eventRecord);
                    }
                }

                ProcessPasswordEvents(recentEvents);
            }
            catch { }
        }

        private void ProcessPasswordEvents(List<EventRecord> events)
        {
            var passwordChangeEvents = events.Where(e => e.Id == 4723 || e.Id == 4724).ToList();
            var failedLoginEvents = events.Where(e => e.Id == 4625).ToList();

            // Detect potential brute force on weak passwords
            if (failedLoginEvents.Count > 10)
            {
                LogPasswordLengthViolation("BRUTE FORCE DETECTED",
                    $"Multiple failed login attempts ({failedLoginEvents.Count}) may indicate weak password attacks",
                    failedLoginEvents.Count, true);
            }

            // Monitor password changes
            foreach (var changeEvent in passwordChangeEvents)
            {
                LogPasswordLengthViolation("PASSWORD CHANGE DETECTED",
                    "Password change event detected - verify compliance with 20-28 character requirement",
                    0, false);
            }
        }

        private void LogPasswordLengthViolation(string violationType, string details, int currentLength, bool isViolation)
        {
            var signal = new be_guardianprotocol.Core.Models.SignalEventLog
            {
                SignalType = SignalTypes.PASSWORD_LENGTH_SECURITY.ToString(),
                Timestamp = DateTime.Now,
                Security = violationType,
                Details = details,
                HipaaViolation = isViolation,
                VpnConnectionCount = currentLength,
                IsConnected = !isViolation
            };

            _logger.LogSignal(signal);
        }
    }
}