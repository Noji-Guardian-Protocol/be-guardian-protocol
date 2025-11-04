using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using System.Runtime.InteropServices;

namespace be_guardianprotocol.Windows
{
    public class WindowsKeyboardDynamicsCollector : ISignalCollector
    {
        private static readonly KeyboardDynamicsAnalyzer _analyzer = new();
        
        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(int vKey);

        private static DateTime _lastKeyTime = DateTime.MinValue;
        private static readonly HashSet<int> _pressedKeys = new();

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();
            var now = DateTime.UtcNow;

            // Check for any key activity (without capturing actual keys)
            var hasKeyActivity = DetectKeyActivity();
            
            if (hasKeyActivity)
            {
                // Calculate inter-key latency
                var interKeyLatency = _lastKeyTime != DateTime.MinValue ? 
                    (now - _lastKeyTime).TotalMilliseconds : 0;

                // Detect error/undo keys (without storing content)
                var isErrorKey = IsErrorKey();
                var isUndoKey = IsUndoKey();
                
                // Get current keyboard layout
                var currentLayout = System.Globalization.CultureInfo.CurrentCulture.Name;

                // Process anonymized key event
                _analyzer.ProcessKeyEvent(isErrorKey, isUndoKey, interKeyLatency, currentLayout);

                _lastKeyTime = now;

                // Generate anonymized profile every 100 key events
                if (_analyzer.GenerateAnonymizedProfile().SampleCount % 100 == 0)
                {
                    var profile = _analyzer.GenerateAnonymizedProfile();
                    await _analyzer.SaveProfileAsync(profile);

                    // Create anonymized signal capture for logging
                    var capture = new SignalCapture
                    {
                        Type = SignalTypes.Keyboard,
                        Name = "KeyboardDynamics",
                        IsConnected = true,
                        
                        // Only metadata - no sensitive content
                        InterKeyDelay = profile.AvgInterKeyLatency,
                        Burstiness = profile.AvgBurstiness,
                        ErrorRate = profile.ErrorRate,
                        LanguageLayout = profile.CurrentLayout,
                        TypingConsistency = profile.TypingConsistency,
                        
                        // Anonymized behavioral vector for ML
                        BehaviorPattern = $"Vector[{string.Join(",", profile.BehavioralVector.Select(v => v.ToString("F3")))}]"
                    };

                    results.Add(capture);
                }
            }

            return results;
        }

        private static bool DetectKeyActivity()
        {
            var currentPressedKeys = new HashSet<int>();

            // Check common keys without capturing content
            for (int vk = 0x08; vk <= 0xFE; vk++)
            {
                if ((GetAsyncKeyState(vk) & 0x8000) != 0)
                {
                    currentPressedKeys.Add(vk);
                }
            }

            // Detect new key presses (activity without content)
            var hasNewActivity = currentPressedKeys.Except(_pressedKeys).Any();
            _pressedKeys.Clear();
            foreach (var key in currentPressedKeys)
                _pressedKeys.Add(key);

            return hasNewActivity;
        }

        private static bool IsErrorKey()
        {
            // Detect backspace/delete without storing content
            return (GetAsyncKeyState(0x08) & 0x8000) != 0 || // Backspace
                   (GetAsyncKeyState(0x2E) & 0x8000) != 0;   // Delete
        }

        private static bool IsUndoKey()
        {
            // Detect Ctrl+Z without storing content
            return (GetAsyncKeyState(0x11) & 0x8000) != 0 && // Ctrl
                   (GetAsyncKeyState(0x5A) & 0x8000) != 0;   // Z
        }
    }
}