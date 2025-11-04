using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Services;
using be_guardianprotocol.Windows;
using be_guardianprotocol.Mac;
using be_guardianprotocol.Linux;
using Microsoft.Extensions.Configuration;
using System.Runtime.InteropServices;

var configuration = new ConfigurationBuilder()
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .Build();

var serviceBusConnectionString = configuration["ServiceBus:ConnectionString"];

var featureEngine = new FeatureExtractionEngine(serviceBusConnectionString);

// Initialize collectors based on platform
var collectors = new List<ISignalCollector>();

if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
{
    var logger = new NetworkConnectionLogger();
    collectors.AddRange(new ISignalCollector[]
    {
        new WindowsApplicationSecurityCollector(),
        new WindowsVpnCollector(),
        new WindowsEncryptionCollector(),
        new WindowsWifiCollector(),
        new WindowsProcessCollector(),
        new WindowsNetworkTrafficCollector(),
        new WindowsKeyboardCollector(),
        new WindowsMouseCollector(),
        new WindowsEndpointProtectionCollector(),
        new WindowsVpnBypassCollector(),
        new WindowsPasswordSecurityCollector(),
        new WindowsGeolocationSecurityCollector(),
        new WindowsHotspotSecurityCollector(),
        new WindowsScreenLockSecurityCollector(),
        new WindowsSessionTimeoutCollector(logger),
        new WindowsPasswordLengthCollector(logger),
        new WindowsMfaSecurityCollector(logger),
        new WindowsPasswordExpirationCollector(logger),
        new WindowsBluetoothCollector(),
        new WindowsTextAnalysisCollector(),
        new WindowsKeyboardDynamicsCollector()
    });
}
else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
{
    collectors.AddRange(new ISignalCollector[]
    {
        new MacApplicationSecurityCollector(),
        new MacVpnCollector(),
        new MacEncryptionCollector(),
        new MacWifiCollector(),
        new MacProcessCollector(),
        new MacNetworkTrafficCollector(),
        new MacKeyboardCollector(),
        new MacMouseCollector(),
        new MacEndpointProtectionCollector(),
        new MacVpnBypassCollector(),
        new MacPasswordSecurityCollector(),
        new MacGeolocationSecurityCollector(),
        new MacHotspotSecurityCollector(),
        new MacScreenLockSecurityCollector(),
        new MacSessionTimeoutCollector(),
        new MacPasswordLengthCollector(),
        new MacMfaSecurityCollector(),
        new MacPasswordExpirationCollector(),
        new MacBluetoothCollector(),
        new MacTextAnalysisCollector(),
        new MacKeyboardDynamicsCollector()
    });
}
else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
{
    collectors.AddRange(new ISignalCollector[]
    {
        new LinuxApplicationSecurityCollector(),
        new LinuxVpnCollector(),
        new LinuxEncryptionCollector(),
        new LinuxWifiCollector(),
        new LinuxProcessCollector(),
        new LinuxNetworkTrafficCollector(),
        new LinuxKeyboardCollector(),
        new LinuxMouseCollector(),
        new LinuxEndpointProtectionCollector(),
        new LinuxVpnBypassCollector(),
        new LinuxPasswordSecurityCollector(),
        new LinuxGeolocationSecurityCollector(),
        new LinuxHotspotSecurityCollector(),
        new LinuxScreenLockSecurityCollector(),
        new LinuxSessionTimeoutCollector(),
        new LinuxPasswordLengthCollector(),
        new LinuxMfaSecurityCollector(),
        new LinuxPasswordExpirationCollector(),
        new LinuxBluetoothCollector(),
        new LinuxTextAnalysisCollector(),
        new LinuxKeyboardDynamicsCollector()
    });
}

var agent = new GuardianProtocolAgent(collectors, featureEngine);

// Service mode - no console output

Console.CancelKeyPress += (_, e) => {
    e.Cancel = true;
    agent.Stop();
};

await agent.StartAsync();