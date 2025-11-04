using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;

namespace be_guardianprotocol.Linux
{
    public class LinuxMouseCollector : ISignalCollector
    {
        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var signals = new List<SignalCapture>();
            
            signals.Add(new SignalCapture
            {
                Type = SignalTypes.Mouse,
                Button = "Left",
                Timestamp = DateTime.Now
            });
            
            return signals;
        }
    }
}