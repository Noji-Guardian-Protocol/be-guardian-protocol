using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.IO;
using System.Threading.Tasks;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;

namespace be_guardianprotocol.Windows
{
    public class WindowsSessionTimeoutCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;
        private readonly Dictionary<string, SessionTimeoutConfig> _config;
        private readonly Dictionary<string, DateTime> _sessionStartTimes = new();
        private readonly Dictionary<string, DateTime> _lastActivityTimes = new();

        [DllImport("user32.dll")]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        [StructLayout(LayoutKind.Sequential)]
        private struct LASTINPUTINFO
        {
            public uint cbSize;
            public uint dwTime;
        }

        public WindowsSessionTimeoutCollector(NetworkConnectionLogger logger)
        {
            _logger = logger;
            _config = LoadConfiguration();
        }

        private Dictionary<string, SessionTimeoutConfig> LoadConfiguration()
        {
            try
            {
                var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "session-timeout-config.json");
                if (File.Exists(configPath))
                {
                    var json = File.ReadAllText(configPath);
                    var config = JsonSerializer.Deserialize<Dictionary<string, SessionTimeoutConfig>>(json);
                    return config ?? new Dictionary<string, SessionTimeoutConfig>();
                }
            }
            catch { }
            return GetDefaultConfiguration();
        }

        private Dictionary<string, SessionTimeoutConfig> GetDefaultConfiguration()
        {
            return new Dictionary<string, SessionTimeoutConfig>
            {
                ["chrome"] = new() { TimeoutMinutes = 30, RequiresReauth = true },
                ["msedge"] = new() { TimeoutMinutes = 30, RequiresReauth = true },
                ["firefox"] = new() { TimeoutMinutes = 30, RequiresReauth = true },
                ["outlook"] = new() { TimeoutMinutes = 60, RequiresReauth = true },
                ["teams"] = new() { TimeoutMinutes = 480, RequiresReauth = false },
                ["excel"] = new() { TimeoutMinutes = 120, RequiresReauth = true },
                ["winword"] = new() { TimeoutMinutes = 120, RequiresReauth = true },
                ["powerpnt"] = new() { TimeoutMinutes = 120, RequiresReauth = true },
                ["ssms"] = new() { TimeoutMinutes = 15, RequiresReauth = true },
                ["mstsc"] = new() { TimeoutMinutes = 30, RequiresReauth = true }
            };
        }

        public async Task<SignalCapture> CollectSignalAsync()
        {
            CollectSessionTimeoutData();
            return new SignalCapture { Type = SignalTypes.SESSION_TIMEOUT_SECURITY };
        }
        
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            CollectSessionTimeoutData();
            return new[] { new SignalCapture { Type = SignalTypes.SESSION_TIMEOUT_SECURITY } };
        }
        
        public void CollectSessionTimeoutData()
        {
            try
            {
                var processes = Process.GetProcesses();
                var currentTime = DateTime.Now;
                var lastInputTime = GetLastInputTime();

                foreach (var process in processes)
                {
                    try
                    {
                        var processName = process.ProcessName.ToLower();
                        if (_config.ContainsKey(processName))
                        {
                            CheckSessionTimeout(process, processName, currentTime, lastInputTime);
                        }
                    }
                    catch { }
                    finally
                    {
                        process?.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                LogSessionTimeoutEvent("SYSTEM", "ERROR", $"Session timeout collection failed: {ex.Message}", 0, false);
            }
        }

        private void CheckSessionTimeout(Process process, string processName, DateTime currentTime, DateTime lastInputTime)
        {
            var sessionKey = $"{processName}_{process.Id}";
            var config = _config[processName];

            if (!_sessionStartTimes.ContainsKey(sessionKey))
            {
                _sessionStartTimes[sessionKey] = process.StartTime;
                _lastActivityTimes[sessionKey] = currentTime;
                return;
            }

            var sessionDuration = currentTime - _sessionStartTimes[sessionKey];
            var lastActivity = _lastActivityTimes[sessionKey] > lastInputTime ? _lastActivityTimes[sessionKey] : lastInputTime;
            var idleDuration = currentTime - lastActivity;

            // Update last activity if there was recent input
            if (lastInputTime > _lastActivityTimes[sessionKey])
            {
                _lastActivityTimes[sessionKey] = lastInputTime;
                idleDuration = TimeSpan.Zero;
            }

            // Check for session timeout violations
            if (idleDuration.TotalMinutes > config.TimeoutMinutes)
            {
                var violationType = config.RequiresReauth ? "SESSION TIMEOUT VIOLATION" : "EXTENDED IDLE SESSION";
                LogSessionTimeoutEvent(processName, violationType, 
                    $"Process {processName} idle for {idleDuration.TotalMinutes:F1} minutes, exceeds limit of {config.TimeoutMinutes} minutes",
                    (int)idleDuration.TotalMinutes, true);
            }

            // Check for excessively long sessions
            if (sessionDuration.TotalHours > 8 && config.RequiresReauth)
            {
                LogSessionTimeoutEvent(processName, "LONG RUNNING SESSION",
                    $"Process {processName} running for {sessionDuration.TotalHours:F1} hours without re-authentication",
                    (int)sessionDuration.TotalMinutes, true);
            }
        }

        private DateTime GetLastInputTime()
        {
            var lastInputInfo = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO)) };
            if (GetLastInputInfo(ref lastInputInfo))
            {
                var tickCount = Environment.TickCount;
                var idleTime = tickCount - lastInputInfo.dwTime;
                return DateTime.Now.AddMilliseconds(-idleTime);
            }
            return DateTime.Now;
        }

        private void LogSessionTimeoutEvent(string processName, string violationType, string details, int idleMinutes, bool isViolation)
        {
            var signal = new be_guardianprotocol.Core.Models.SignalEventLog
            {
                SignalType = SignalTypes.SESSION_TIMEOUT_SECURITY.ToString(),
                Timestamp = DateTime.Now,
                ProcessName = processName,
                Security = violationType,
                Details = details,
                HipaaViolation = isViolation,
                VpnConnectionCount = idleMinutes,
                IsConnected = !isViolation
            };

            _logger.LogSignal(signal);
        }

        private class SessionTimeoutConfig
        {
            public int TimeoutMinutes { get; set; }
            public bool RequiresReauth { get; set; }
        }
    }
}