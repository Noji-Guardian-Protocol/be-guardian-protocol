using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Services;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace be_guardianprotocol.Windows
{
    public class WindowsMouseCollector : ISignalCollector
    {
        private static readonly NetworkConnectionLogger _logger = new();
        [DllImport("user32.dll")]
        private static extern bool GetCursorPos(out POINT lpPoint);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);

        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(int vKey);

        private const int VK_LBUTTON = 0x01;
        private const int VK_RBUTTON = 0x02;
        private const int VK_MBUTTON = 0x04;
        private const int VK_XBUTTON1 = 0x05;
        private const int VK_XBUTTON2 = 0x06;

        [StructLayout(LayoutKind.Sequential)]
        public struct POINT
        {
            public int X;
            public int Y;
        }

        private static POINT _lastPosition;
        private static DateTime _lastCaptureTime = DateTime.Now;
        private static readonly List<POINT> _recentPositions = new();
        private static string? _lastButtonState;
        private static int _clickCount = 0;
        private static DateTime _lastClickTime = DateTime.MinValue;

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();

            // Get current mouse position
            if (GetCursorPos(out POINT currentPos))
            {
                var capture = new SignalCapture
                {
                    Type = SignalTypes.Mouse,
                    IsConnected = true,
                    PositionX = currentPos.X,
                    PositionY = currentPos.Y,
                    DeltaX = currentPos.X - _lastPosition.X,
                    DeltaY = currentPos.Y - _lastPosition.Y
                };

                // Calculate movement speed and distance
                var timeDiff = (DateTime.Now - _lastCaptureTime).TotalSeconds;
                var distance = Math.Sqrt(Math.Pow(capture.DeltaX ?? 0, 2) + Math.Pow(capture.DeltaY ?? 0, 2));
                capture.DistanceTraveled = distance;
                
                if (timeDiff > 0)
                {
                    capture.MovementSpeed = distance / timeDiff;
                }

                // Analyze movement patterns
                capture.MovementDirection = GetMovementDirection(capture.DeltaX ?? 0, capture.DeltaY ?? 0);
                capture.ScreenRegion = GetScreenRegion(currentPos.X, currentPos.Y);
                capture.IsIdle = distance < 5 && timeDiff > 2;
                capture.ActivityType = DetermineActivityType(capture, distance);
                capture.BehaviorPattern = AnalyzeBehaviorPattern(currentPos, capture.Button);

                // Get active window
                capture.ActiveWindow = GetActiveWindowTitle();

                // Get mouse button states and detect clicks
                var buttonInfo = GetMouseButtonState();
                capture.Button = buttonInfo.Button;
                capture.ButtonState = buttonInfo.ButtonState;
                capture.IsDragging = !string.IsNullOrEmpty(buttonInfo.Button) && distance > 0;
                
                // Track click patterns
                if (buttonInfo.ButtonState == "Pressed" && _lastButtonState != "Pressed")
                {
                    var clickInterval = (DateTime.Now - _lastClickTime).TotalMilliseconds;
                    if (clickInterval < 500) _clickCount++; else _clickCount = 1;
                    _lastClickTime = DateTime.Now;
                    
                    capture.ClickType = _clickCount > 1 ? "DoubleClick" : "SingleClick";
                }
                else if (capture.IsDragging == true)
                {
                    capture.ClickType = "Drag";
                }
                
                _lastButtonState = buttonInfo.ButtonState;

                // Get mouse device info
                var deviceInfo = await GetMouseDeviceInfo();
                capture.DeviceName = deviceInfo.DeviceName;
                capture.ConnectionType = deviceInfo.ConnectionType;

                // Track position history
                _recentPositions.Add(currentPos);
                if (_recentPositions.Count > 10) _recentPositions.RemoveAt(0);
                
                _lastPosition = currentPos;
                _lastCaptureTime = DateTime.Now;

                // Log all mouse events
                await _logger.LogConnectionAsync(capture);

                results.Add(capture);
            }

            return results;
        }

        private static (string? Button, string? ButtonState) GetMouseButtonState()
        {
            var pressedButtons = new List<string>();
            
            if ((GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0)
                pressedButtons.Add("Left");
            if ((GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0)
                pressedButtons.Add("Right");
            if ((GetAsyncKeyState(VK_MBUTTON) & 0x8000) != 0)
                pressedButtons.Add("Middle");
            if ((GetAsyncKeyState(VK_XBUTTON1) & 0x8000) != 0)
                pressedButtons.Add("X1");
            if ((GetAsyncKeyState(VK_XBUTTON2) & 0x8000) != 0)
                pressedButtons.Add("X2");

            if (pressedButtons.Count > 0)
            {
                return (string.Join("+", pressedButtons), "Pressed");
            }

            return (null, "Released");
        }

        private static string? GetActiveWindowTitle()
        {
            try
            {
                var hwnd = GetForegroundWindow();
                var text = new System.Text.StringBuilder(256);
                return GetWindowText(hwnd, text, text.Capacity) > 0 ? text.ToString() : null;
            }
            catch
            {
                return null;
            }
        }

        private static async Task<(string? DeviceName, string? ConnectionType)> GetMouseDeviceInfo()
        {
            try
            {
                var output = await RunCommandAsync("wmic", "path win32_pointingdevice get name,deviceinterface /format:csv");
                var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                
                foreach (var line in lines.Skip(1))
                {
                    var parts = line.Split(',');
                    if (parts.Length >= 3 && !string.IsNullOrWhiteSpace(parts[2]))
                    {
                        var deviceName = parts[2].Trim();
                        var connectionType = DetermineConnectionType(deviceName);
                        return (deviceName, connectionType);
                    }
                }
            }
            catch
            {
                // Silent fail
            }

            return ("Unknown Mouse", "Unknown");
        }

        private static string DetermineConnectionType(string deviceName)
        {
            var lowerName = deviceName.ToLower();
            if (lowerName.Contains("usb")) return "USB";
            if (lowerName.Contains("bluetooth") || lowerName.Contains("bt")) return "Bluetooth";
            if (lowerName.Contains("wireless") || lowerName.Contains("rf")) return "Wireless";
            if (lowerName.Contains("ps/2")) return "PS/2";
            return "Unknown";
        }

        private static string GetMovementDirection(int deltaX, int deltaY)
        {
            if (Math.Abs(deltaX) < 2 && Math.Abs(deltaY) < 2) return "Stationary";
            if (Math.Abs(deltaX) > Math.Abs(deltaY))
                return deltaX > 0 ? "Right" : "Left";
            else
                return deltaY > 0 ? "Down" : "Up";
        }

        private static string GetScreenRegion(int x, int y)
        {
            // Assume 1920x1080 screen for regions
            var screenWidth = 1920;
            var screenHeight = 1080;
            
            var regionX = x < screenWidth / 3 ? "Left" : x > 2 * screenWidth / 3 ? "Right" : "Center";
            var regionY = y < screenHeight / 3 ? "Top" : y > 2 * screenHeight / 3 ? "Bottom" : "Middle";
            
            return $"{regionY}-{regionX}";
        }

        private static string DetermineActivityType(SignalCapture capture, double distance)
        {
            if (capture.IsIdle == true) return "Idle";
            if (!string.IsNullOrEmpty(capture.Button)) return "Clicking";
            if (distance > 50) return "FastMovement";
            if (distance > 10) return "NormalMovement";
            return "SlowMovement";
        }

        private static string AnalyzeBehaviorPattern(POINT currentPos, string? button)
        {
            if (_recentPositions.Count < 5) return "Initializing";
            
            var isCircular = IsCircularMovement();
            var isLinear = IsLinearMovement();
            var isErratic = IsErraticMovement();
            
            if (!string.IsNullOrEmpty(button)) return "Interactive";
            if (isCircular) return "Circular";
            if (isLinear) return "Linear";
            if (isErratic) return "Erratic";
            return "Normal";
        }

        private static bool IsCircularMovement()
        {
            if (_recentPositions.Count < 8) return false;
            var directions = new List<string>();
            for (int i = 1; i < _recentPositions.Count; i++)
            {
                var dx = _recentPositions[i].X - _recentPositions[i-1].X;
                var dy = _recentPositions[i].Y - _recentPositions[i-1].Y;
                directions.Add(GetMovementDirection(dx, dy));
            }
            return directions.Distinct().Count() >= 3;
        }

        private static bool IsLinearMovement()
        {
            if (_recentPositions.Count < 5) return false;
            var directions = new List<string>();
            for (int i = 1; i < _recentPositions.Count; i++)
            {
                var dx = _recentPositions[i].X - _recentPositions[i-1].X;
                var dy = _recentPositions[i].Y - _recentPositions[i-1].Y;
                directions.Add(GetMovementDirection(dx, dy));
            }
            return directions.Distinct().Count() <= 2;
        }

        private static bool IsErraticMovement()
        {
            if (_recentPositions.Count < 5) return false;
            var totalDistance = 0.0;
            for (int i = 1; i < _recentPositions.Count; i++)
            {
                var dx = _recentPositions[i].X - _recentPositions[i-1].X;
                var dy = _recentPositions[i].Y - _recentPositions[i-1].Y;
                totalDistance += Math.Sqrt(dx * dx + dy * dy);
            }
            return totalDistance > 200; // High movement in short time
        }

        private static async Task<string> RunCommandAsync(string cmd, string args)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = cmd,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                }
            };
            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
            return output;
        }
    }
}