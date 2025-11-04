using be_guardianprotocol.Core.Models;

namespace be_guardianprotocol.Core.Interfaces
{
    public interface ISignalCollector
    {
        Task<IEnumerable<SignalCapture>> CollectAsync();
    }
}
