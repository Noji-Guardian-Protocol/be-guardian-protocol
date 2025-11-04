using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace be_guardianprotocol.Windows
{
    public class WindowsPasswordSecurityCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;
        private readonly PasswordSecurityConfig _config;
        private static Dictionary<string, List<DateTime>> _failedAttempts = new();
        private static Dictionary<string, int> _bruteForceAttempts = new();

        public WindowsPasswordSecurityCollector()
        {
            _logger = new NetworkConnectionLogger();
            _config = LoadConfig();
        }

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();

            try
            {
                var authEvents = await GetAuthenticationEventsAsync();
                var passwordPolicyViolations = await CheckPasswordPolicyComplianceAsync();
                var bruteForceDetection = AnalyzeBruteForcePatterns(authEvents);

                if (authEvents.Any() || passwordPolicyViolations.Any() || bruteForceDetection.IsBruteForceDetected)
                {
                    var capture = new SignalCapture
                    {
                        Type = SignalTypes.PASSWORD_SECURITY,
                        IsConnected = false,
                        Timestamp = DateTime.Now,
                        Security = BuildSecurityMessage(authEvents, passwordPolicyViolations, bruteForceDetection),
                        HipaaViolation = true,
                        ComplianceRule = "HIPAA 164.312(a)(1) & 164.312(d)",
                        MitreTactic = "Credential Access, Initial Access",
                        MitreTechnique = "T1110 - Brute Force, T1555 - Credentials from Password Stores, T1078 - Valid Accounts",
                        ThreatDetected = "AN1521 - Password Guessing via Authentication Failures",
                        VpnConnectionCount = bruteForceDetection.FailedAttemptCount
                    };

                    await _logger.LogConnectionAsync(capture);
                    results.Add(capture);
                }
            }
            catch (Exception ex)
            {
                var errorCapture = new SignalCapture
                {
                    Type = SignalTypes.PASSWORD_SECURITY,
                    IsConnected = false,
                    Timestamp = DateTime.Now,
                    ErrorMessage = ex.Message
                };
                results.Add(errorCapture);
            }

            return results;
        }

        private async Task<List<AuthenticationEvent>> GetAuthenticationEventsAsync()
        {
            var events = new List<AuthenticationEvent>();

            try
            {
                var eventLogQuery = await RunCommandAsync("wevtutil", 
                    "qe Security /c:100 /f:text /q:\"*[System[EventID=4625 or EventID=4624 or EventID=4723 or EventID=4724]]\"");

                if (!string.IsNullOrEmpty(eventLogQuery))
                {
                    events.AddRange(ParseAuthenticationEvents(eventLogQuery));
                }
            }
            catch { /* Silent fail */ }

            return events;
        }

        private List<AuthenticationEvent> ParseAuthenticationEvents(string eventLogData)
        {
            var events = new List<AuthenticationEvent>();
            var eventBlocks = eventLogData.Split(new[] { "Event[" }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var block in eventBlocks)
            {
                try
                {
                    var eventIdMatch = Regex.Match(block, @"EventID:\s*(\d+)");
                    var userMatch = Regex.Match(block, @"Account Name:\s*([^\r\n]+)");
                    var sourceIpMatch = Regex.Match(block, @"Source Network Address:\s*([^\r\n]+)");
                    var timeMatch = Regex.Match(block, @"Date:\s*([^\r\n]+)");

                    if (eventIdMatch.Success && userMatch.Success)
                    {
                        var eventId = int.Parse(eventIdMatch.Groups[1].Value);
                        var username = userMatch.Groups[1].Value.Trim();
                        var sourceIp = sourceIpMatch.Success ? sourceIpMatch.Groups[1].Value.Trim() : "";

                        if (IsWeakPasswordPattern(username) || eventId == 4625)
                        {
                            events.Add(new AuthenticationEvent
                            {
                                EventId = eventId,
                                Username = username,
                                SourceIP = sourceIp,
                                Timestamp = DateTime.Now,
                                IsFailure = eventId == 4625,
                                IsWeakPattern = IsWeakPasswordPattern(username)
                            });
                        }
                    }
                }
                catch { /* Skip malformed events */ }
            }

            return events;
        }

        private async Task<List<PasswordPolicyViolation>> CheckPasswordPolicyComplianceAsync()
        {
            var violations = new List<PasswordPolicyViolation>();

            try
            {
                var policyCheck = await RunCommandAsync("net", "accounts");
                
                if (policyCheck.Contains("Minimum password length: 0") || 
                    policyCheck.Contains("Password complexity: No"))
                {
                    violations.Add(new PasswordPolicyViolation
                    {
                        ViolationType = "WEAK_POLICY",
                        Description = "Password complexity requirements disabled"
                    });
                }

                var userAccounts = await RunCommandAsync("net", "user");
                var users = ParseUserAccounts(userAccounts);
                
                foreach (var user in users)
                {
                    if (IsServiceAccount(user) && IsWeakPasswordPattern(user))
                    {
                        violations.Add(new PasswordPolicyViolation
                        {
                            ViolationType = "WEAK_SERVICE_ACCOUNT",
                            Description = $"Service account with weak naming: {user}",
                            Username = user
                        });
                    }
                }
            }
            catch { /* Silent fail */ }

            return violations;
        }

        private BruteForceAnalysis AnalyzeBruteForcePatterns(List<AuthenticationEvent> events)
        {
            var analysis = new BruteForceAnalysis();
            var now = DateTime.Now;
            var timeWindow = TimeSpan.FromMinutes(_config.TimeWindowMinutes);

            foreach (var evt in events.Where(e => e.IsFailure))
            {
                var key = $"{evt.Username}_{evt.SourceIP}";
                
                if (!_failedAttempts.ContainsKey(key))
                    _failedAttempts[key] = new List<DateTime>();

                _failedAttempts[key].Add(evt.Timestamp);
                
                // Clean old attempts outside time window
                _failedAttempts[key] = _failedAttempts[key]
                    .Where(t => now - t <= timeWindow).ToList();

                if (_failedAttempts[key].Count >= _config.FailedAttemptThreshold)
                {
                    analysis.IsBruteForceDetected = true;
                    analysis.FailedAttemptCount = _failedAttempts[key].Count;
                    analysis.TargetUsername = evt.Username;
                    analysis.SourceIP = evt.SourceIP;
                    
                    _bruteForceAttempts[key] = _failedAttempts[key].Count;
                }
            }

            return analysis;
        }

        private bool IsWeakPasswordPattern(string username)
        {
            var weakPatterns = _config.WeakPasswordPatterns;
            return weakPatterns.Any(pattern => 
                username.ToLower().Contains(pattern.ToLower()));
        }

        private bool IsServiceAccount(string username)
        {
            var servicePatterns = new[] { "svc", "service", "admin", "administrator", "sa", "root" };
            return servicePatterns.Any(pattern => 
                username.ToLower().Contains(pattern));
        }

        private List<string> ParseUserAccounts(string netUserOutput)
        {
            var users = new List<string>();
            var lines = netUserOutput.Split('\n');
            
            foreach (var line in lines)
            {
                if (line.Contains("User accounts for"))
                    continue;
                    
                var userMatches = Regex.Matches(line, @"\b[a-zA-Z][a-zA-Z0-9_-]*\b");
                foreach (Match match in userMatches)
                {
                    if (match.Value.Length > 2 && !match.Value.Equals("The", StringComparison.OrdinalIgnoreCase))
                        users.Add(match.Value);
                }
            }
            
            return users.Distinct().ToList();
        }

        private string BuildSecurityMessage(List<AuthenticationEvent> authEvents, 
            List<PasswordPolicyViolation> policyViolations, BruteForceAnalysis bruteForce)
        {
            var messages = new List<string>();

            if (authEvents.Any(e => e.IsWeakPattern))
            {
                messages.Add($"WEAK PASSWORD PATTERN: {authEvents.Count(e => e.IsWeakPattern)} accounts");
            }

            if (policyViolations.Any())
            {
                messages.Add($"POLICY VIOLATION: {string.Join(", ", policyViolations.Select(v => v.ViolationType))}");
            }

            if (bruteForce.IsBruteForceDetected)
            {
                messages.Add($"BRUTE FORCE: {bruteForce.FailedAttemptCount} attempts on {bruteForce.TargetUsername}");
            }

            var failedLogins = authEvents.Count(e => e.IsFailure);
            if (failedLogins > 0)
            {
                messages.Add($"FAILED LOGINS: {failedLogins} attempts");
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

        private PasswordSecurityConfig LoadConfig()
        {
            try
            {
                var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "password-security-config.json");
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    return JsonSerializer.Deserialize<PasswordSecurityConfig>(json) ?? new PasswordSecurityConfig();
                }
            }
            catch { /* Silent fail */ }

            return new PasswordSecurityConfig();
        }
    }

    public class PasswordSecurityConfig
    {
        public List<string> WeakPasswordPatterns { get; set; } = new()
        {
            "password", "123456", "admin", "user", "guest", "test", "temp", "default",
            "welcome", "login", "pass", "root", "administrator", "qwerty", "abc123"
        };

        public int TimeWindowMinutes { get; set; } = 10;
        public int FailedAttemptThreshold { get; set; } = 5;
        public int SourceIPThreshold { get; set; } = 3;
    }

    public class AuthenticationEvent
    {
        public int EventId { get; set; }
        public string Username { get; set; } = "";
        public string SourceIP { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public bool IsFailure { get; set; }
        public bool IsWeakPattern { get; set; }
    }

    public class PasswordPolicyViolation
    {
        public string ViolationType { get; set; } = "";
        public string Description { get; set; } = "";
        public string Username { get; set; } = "";
    }

    public class BruteForceAnalysis
    {
        public bool IsBruteForceDetected { get; set; }
        public int FailedAttemptCount { get; set; }
        public string TargetUsername { get; set; } = "";
        public string SourceIP { get; set; } = "";
    }
}