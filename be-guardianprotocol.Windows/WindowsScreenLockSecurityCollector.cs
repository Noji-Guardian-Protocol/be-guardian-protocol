using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace be_guardianprotocol.Windows
{
    public class WindowsScreenLockSecurityCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;
        private readonly ScreenLockConfig _config;
        private static DateTime _lastActivityTime = DateTime.Now;

        [DllImport("user32.dll")]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        [DllImport("kernel32.dll")]
        private static extern uint GetTickCount();

        [StructLayout(LayoutKind.Sequential)]
        private struct LASTINPUTINFO
        {
            public uint cbSize;
            public uint dwTime;
        }

        public WindowsScreenLockSecurityCollector()
        {
            _logger = new NetworkConnectionLogger();
            _config = LoadConfig();
        }

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();

            try
            {
                var policyViolations = await CheckScreenLockPoliciesAsync();
                var idleTimeAnalysis = GetIdleTimeAnalysis();
                var sessionState = await GetSessionStateAsync();

                if (policyViolations.Any() || idleTimeAnalysis.IsViolation || sessionState.IsUnlockedTooLong)
                {
                    var capture = new SignalCapture
                    {
                        Type = SignalTypes.SCREEN_LOCK_SECURITY,
                        IsConnected = false,
                        Timestamp = DateTime.Now,
                        Security = BuildSecurityMessage(policyViolations, idleTimeAnalysis, sessionState),
                        HipaaViolation = true,
                        ComplianceRule = "HIPAA 164.312(a)(1) & 164.308(a)(1)",
                        MitreTactic = "Defense Evasion, Initial Access",
                        MitreTechnique = "T1543 - Modify System Process, T1562.001 - Disable Security Controls, T1078 - Valid Accounts",
                        ThreatDetected = "Screen Lock Policy Violation",
                        VpnConnectionCount = (int)idleTimeAnalysis.IdleTimeMinutes
                    };

                    await _logger.LogConnectionAsync(capture);
                    results.Add(capture);
                }
            }
            catch (Exception ex)
            {
                var errorCapture = new SignalCapture
                {
                    Type = SignalTypes.SCREEN_LOCK_SECURITY,
                    IsConnected = false,
                    Timestamp = DateTime.Now,
                    ErrorMessage = ex.Message
                };
                results.Add(errorCapture);
            }

            return results;
        }

        private async Task<List<ScreenLockPolicyViolation>> CheckScreenLockPoliciesAsync()
        {
            var violations = new List<ScreenLockPolicyViolation>();

            try
            {
                // Check screensaver timeout policy
                var screensaverTimeout = GetRegistryValue(@"HKEY_CURRENT_USER\Control Panel\Desktop", "ScreenSaveTimeOut");
                if (string.IsNullOrEmpty(screensaverTimeout) || !int.TryParse(screensaverTimeout, out var timeout) || timeout == 0 || timeout > _config.MaxScreensaverTimeoutSeconds)
                {
                    var timeoutValue = int.TryParse(screensaverTimeout, out var parsedTimeout) ? parsedTimeout : 0;
                    violations.Add(new ScreenLockPolicyViolation
                    {
                        ViolationType = "SCREENSAVER_TIMEOUT",
                        Description = $"Screensaver timeout disabled or exceeds policy ({timeoutValue}s > {_config.MaxScreensaverTimeoutSeconds}s)",
                        CurrentValue = screensaverTimeout ?? "0",
                        ExpectedValue = _config.MaxScreensaverTimeoutSeconds.ToString()
                    });
                }

                // Check screensaver secure flag
                var screensaverSecure = GetRegistryValue(@"HKEY_CURRENT_USER\Control Panel\Desktop", "ScreenSaverIsSecure");
                if (screensaverSecure != "1")
                {
                    violations.Add(new ScreenLockPolicyViolation
                    {
                        ViolationType = "SCREENSAVER_NOT_SECURE",
                        Description = "Screensaver does not require password on resume",
                        CurrentValue = screensaverSecure ?? "0",
                        ExpectedValue = "1"
                    });
                }

                // Check automatic lock policy
                var lockTimeout = GetRegistryValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs");
                if (string.IsNullOrEmpty(lockTimeout) || !int.TryParse(lockTimeout, out var lockTimeoutValue) || lockTimeoutValue == 0 || lockTimeoutValue > _config.MaxLockTimeoutSeconds)
                {
                    var lockValue = int.TryParse(lockTimeout, out var parsedLockTimeout) ? parsedLockTimeout : 0;
                    violations.Add(new ScreenLockPolicyViolation
                    {
                        ViolationType = "AUTO_LOCK_TIMEOUT",
                        Description = $"Auto-lock timeout disabled or exceeds policy ({lockValue}s > {_config.MaxLockTimeoutSeconds}s)",
                        CurrentValue = lockTimeout ?? "0",
                        ExpectedValue = _config.MaxLockTimeoutSeconds.ToString()
                    });
                }

                // Check if screensaver is enabled
                var screensaverActive = GetRegistryValue(@"HKEY_CURRENT_USER\Control Panel\Desktop", "ScreenSaveActive");
                if (screensaverActive != "1")
                {
                    violations.Add(new ScreenLockPolicyViolation
                    {
                        ViolationType = "SCREENSAVER_DISABLED",
                        Description = "Screensaver is disabled",
                        CurrentValue = screensaverActive ?? "0",
                        ExpectedValue = "1"
                    });
                }
            }
            catch { /* Silent fail */ }

            return violations;
        }

        private IdleTimeAnalysis GetIdleTimeAnalysis()
        {
            var analysis = new IdleTimeAnalysis();

            try
            {
                var lastInputInfo = new LASTINPUTINFO();
                lastInputInfo.cbSize = (uint)Marshal.SizeOf(lastInputInfo);
                
                if (GetLastInputInfo(ref lastInputInfo))
                {
                    var currentTickCount = GetTickCount();
                    var idleTimeMs = currentTickCount - lastInputInfo.dwTime;
                    analysis.IdleTimeMinutes = idleTimeMs / (1000.0 * 60.0);
                    
                    // Check if idle time exceeds policy
                    if (analysis.IdleTimeMinutes > _config.MaxIdleTimeMinutes)
                    {
                        analysis.IsViolation = true;
                        analysis.ViolationType = "EXTENDED_IDLE_SESSION";
                    }
                }
            }
            catch { /* Silent fail */ }

            return analysis;
        }

        private async Task<SessionState> GetSessionStateAsync()
        {
            var state = new SessionState();

            try
            {
                // Check if workstation is locked
                var isLocked = await IsWorkstationLockedAsync();
                state.IsLocked = isLocked;
                
                // Check session duration
                var sessionDuration = await GetSessionDurationAsync();
                state.SessionDurationMinutes = sessionDuration;
                
                // Determine if unlocked too long
                if (!isLocked && sessionDuration > _config.MaxUnlockedSessionMinutes)
                {
                    state.IsUnlockedTooLong = true;
                }
            }
            catch { /* Silent fail */ }

            return state;
        }

        private async Task<bool> IsWorkstationLockedAsync()
        {
            try
            {
                // Check if logon screen is active
                var queryUser = await RunCommandAsync("query", "user");
                return queryUser.Contains("Disc") || queryUser.Contains("Disconnected");
            }
            catch
            {
                return false;
            }
        }

        private async Task<double> GetSessionDurationAsync()
        {
            try
            {
                var queryUser = await RunCommandAsync("query", "user");
                var lines = queryUser.Split('\n');
                
                foreach (var line in lines)
                {
                    if (line.Contains(Environment.UserName) && line.Contains("Active"))
                    {
                        // Parse session start time (simplified)
                        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length > 6)
                        {
                            // Extract time information and calculate duration
                            return (DateTime.Now - DateTime.Today).TotalMinutes; // Simplified
                        }
                    }
                }
            }
            catch { /* Silent fail */ }

            return 0;
        }

        private string GetRegistryValue(string keyPath, string valueName)
        {
            try
            {
                var key = keyPath.StartsWith("HKEY_CURRENT_USER") 
                    ? Registry.CurrentUser.OpenSubKey(keyPath.Replace("HKEY_CURRENT_USER\\", ""))
                    : Registry.LocalMachine.OpenSubKey(keyPath.Replace("HKEY_LOCAL_MACHINE\\", ""));
                
                return key?.GetValue(valueName)?.ToString() ?? "";
            }
            catch
            {
                return "";
            }
        }

        private string BuildSecurityMessage(List<ScreenLockPolicyViolation> violations, IdleTimeAnalysis idleTime, SessionState session)
        {
            var messages = new List<string>();

            if (violations.Any(v => v.ViolationType == "SCREENSAVER_DISABLED"))
            {
                messages.Add("SCREENSAVER DISABLED");
            }

            if (violations.Any(v => v.ViolationType == "SCREENSAVER_TIMEOUT"))
            {
                var violation = violations.First(v => v.ViolationType == "SCREENSAVER_TIMEOUT");
                messages.Add($"SCREENSAVER TIMEOUT: {violation.CurrentValue}s");
            }

            if (violations.Any(v => v.ViolationType == "SCREENSAVER_NOT_SECURE"))
            {
                messages.Add("SCREENSAVER NOT SECURE");
            }

            if (violations.Any(v => v.ViolationType == "AUTO_LOCK_TIMEOUT"))
            {
                var violation = violations.First(v => v.ViolationType == "AUTO_LOCK_TIMEOUT");
                messages.Add($"AUTO-LOCK TIMEOUT: {violation.CurrentValue}s");
            }

            if (idleTime.IsViolation)
            {
                messages.Add($"EXTENDED IDLE: {idleTime.IdleTimeMinutes:F1} minutes");
            }

            if (session.IsUnlockedTooLong)
            {
                messages.Add($"UNLOCKED TOO LONG: {session.SessionDurationMinutes:F1} minutes");
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

        private ScreenLockConfig LoadConfig()
        {
            try
            {
                var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "screen-lock-config.json");
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    return JsonSerializer.Deserialize<ScreenLockConfig>(json) ?? new ScreenLockConfig();
                }
            }
            catch { /* Silent fail */ }

            return new ScreenLockConfig();
        }
    }

    public class ScreenLockConfig
    {
        public int MaxScreensaverTimeoutSeconds { get; set; } = 900; // 15 minutes
        public int MaxLockTimeoutSeconds { get; set; } = 900; // 15 minutes
        public double MaxIdleTimeMinutes { get; set; } = 15;
        public double MaxUnlockedSessionMinutes { get; set; } = 480; // 8 hours
    }

    public class ScreenLockPolicyViolation
    {
        public string ViolationType { get; set; } = "";
        public string Description { get; set; } = "";
        public string CurrentValue { get; set; } = "";
        public string ExpectedValue { get; set; } = "";
    }

    public class IdleTimeAnalysis
    {
        public double IdleTimeMinutes { get; set; }
        public bool IsViolation { get; set; }
        public string ViolationType { get; set; } = "";
    }

    public class SessionState
    {
        public bool IsLocked { get; set; }
        public double SessionDurationMinutes { get; set; }
        public bool IsUnlockedTooLong { get; set; }
    }
}