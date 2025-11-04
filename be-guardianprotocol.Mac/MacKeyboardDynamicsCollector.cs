using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;

namespace be_guardianprotocol.Mac
{
    public class MacKeyboardDynamicsCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            signals.Add(new SignalCapture
            {
                Type = SignalTypes.Keyboard,
                InterKeyLatency = 0,
                TypingSpeed = 0,
                Timestamp = DateTime.Now
            });
            
            return signals;
        }
    }
}