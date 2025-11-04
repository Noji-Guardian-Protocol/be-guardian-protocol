using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using SharpHook;
using SharpHook.Native;
using System.Diagnostics;

namespace be_guardianprotocol.Windows
{
    public class WindowsKeyboardCollector : ISignalCollector
    {
        private static readonly NetworkConnectionLogger _logger = new();
        private static readonly List<SignalCapture> _capturedKeys = new();
        private static IGlobalHook? _hook;
        private static DateTime _lastKeyTime = DateTime.MinValue;
        private static string? _lastKeyPressed;

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            if (_hook == null)
            {
                _hook = new TaskPoolGlobalHook();
                _hook.KeyPressed += OnKeyPressed;
                await _hook.RunAsync();
            }

            var results = new List<SignalCapture>(_capturedKeys);
            _capturedKeys.Clear();
            return results;
        }

        private static async void OnKeyPressed(object? sender, KeyboardHookEventArgs e)
        {
            var keyName = e.Data.KeyCode.ToString();
            var now = DateTime.Now;
            
            var capture = new SignalCapture
            {
                Type = SignalTypes.Keyboard,
                IsConnected = true,
                KeyPressed = keyName,
                KeyState = "Pressed",
                Timestamp = now,
                KeyCode = (int)e.Data.KeyCode,
                ActiveWindow = GetActiveWindowTitle()
            };

            // Add timing analysis
            if (_lastKeyTime != DateTime.MinValue)
            {
                capture.InterKeyLatency = (now - _lastKeyTime).TotalMilliseconds;
            }
            
            // Categorize key type
            capture.KeyCategory = CategorizeKey(keyName);
            capture.IsModifierKey = keyName is "LeftShift" or "RightShift" or "LeftControl" or "RightControl" or "LeftAlt" or "RightAlt";
            
            _lastKeyTime = now;
            _lastKeyPressed = keyName;

            // Log keyboard event
            await _logger.LogConnectionAsync(capture);

            _capturedKeys.Add(capture);
        }

        private static string CategorizeKey(string key)
        {
            if (key.Contains("Shift") || key.Contains("Control") || key.Contains("Alt")) return "Modifier";
            if (key.StartsWith("F") && key.Length <= 3) return "Function";
            if (key.Contains("Arrow") || key is "Home" or "End" or "PageUp" or "PageDown") return "Navigation";
            if (key is "Enter" or "Tab" or "Space") return "Whitespace";
            if (key is "Backspace" or "Delete") return "Editing";
            if (char.IsLetter(key.FirstOrDefault())) return "Letter";
            if (char.IsDigit(key.FirstOrDefault())) return "Number";
            return "Special";
        }

        private static string? GetActiveWindowTitle()
        {
            try
            {
                var processes = Process.GetProcesses();
                var activeProcess = processes.FirstOrDefault(p => !string.IsNullOrEmpty(p.MainWindowTitle));
                return activeProcess?.MainWindowTitle;
            }
            catch
            {
                return null;
            }
        }
    }
}