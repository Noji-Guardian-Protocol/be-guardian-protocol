using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Enums;

namespace be_guardianprotocol.Mac
{
    public class MacKeyboardCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            signals.Add(new SignalCapture
            {
                Type = SignalTypes.Keyboard,
                Security = "Mac keyboard monitoring not implemented",
                Timestamp = DateTime.Now
            });
            
            return signals;
        }
    }
}