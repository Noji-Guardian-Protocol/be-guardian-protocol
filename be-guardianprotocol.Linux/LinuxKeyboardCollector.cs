using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;

namespace be_guardianprotocol.Linux
{
    public class LinuxKeyboardCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            signals.Add(new SignalCapture
            {
                Type = SignalTypes.Keyboard,
                KeyPressed = "placeholder",
                Timestamp = DateTime.Now
            });
            
            return signals;
        }
    }
}