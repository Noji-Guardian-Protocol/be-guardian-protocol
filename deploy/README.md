# Guardian Protocol Agent Deployment

## Prerequisites

### Windows
- Administrator privileges required
- .NET 9.0 Runtime (included in self-contained build)

### macOS
- sudo privileges required
- macOS 10.15+ (Catalina or later)

### Linux
- sudo privileges required
- systemd-based distribution (Ubuntu, CentOS, RHEL, etc.)

## Deployment Process

### 1. Build Packages
```powershell
powershell deploy/build-packages.ps1
```
This creates compiled executables for each platform:
- `deploy/windows/` - Contains `be-guardianprotocol.Console.exe` + DLLs
- `deploy/mac/` - Contains `be-guardianprotocol.Console` (executable) + DLLs
- `deploy/linux/` - Contains `be-guardianprotocol.Console` (executable) + DLLs

### 2. Copy Deployment Folders
Copy the appropriate deployment folder to each target system:
- Copy entire `deploy/windows/` folder to Windows machine
- Copy entire `deploy/mac/` folder to Mac machine
- Copy entire `deploy/linux/` folder to Linux machine

### 3. Run Installation Script
On each target system, run the installation script:
- **Windows**: `install.bat` (as Administrator)
- **macOS**: `sudo bash install.sh`
- **Linux**: `sudo bash install.sh`

## Files Deployed
- **Executable**: Platform-specific compiled binary (no source code)
- **Libraries**: Required .NET DLLs (self-contained)
- **Configuration**: `appsettings.json`

## Installation Locations
- **Windows**: `C:\Program Files\GuardianProtocol\`
- **macOS**: `/usr/local/bin/guardianprotocol/`
- **Linux**: `/opt/guardianprotocol/`

## Service Management

### Windows
```cmd
sc start GuardianProtocol
sc stop GuardianProtocol
sc delete GuardianProtocol
```

### macOS
```bash
sudo launchctl start com.guardianprotocol.agent
sudo launchctl stop com.guardianprotocol.agent
sudo launchctl unload /Library/LaunchDaemons/com.guardianprotocol.agent.plist
```

### Linux
```bash
sudo systemctl start guardianprotocol
sudo systemctl stop guardianprotocol
sudo systemctl disable guardianprotocol
```

## Configuration

Edit `appsettings.json` in the installation directory to configure Service Bus connection.