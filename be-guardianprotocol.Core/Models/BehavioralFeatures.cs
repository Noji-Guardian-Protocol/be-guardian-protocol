using System.Collections.Generic;
using System.Management;
using System.Text;

namespace be_guardianprotocol.Core.Models
{
    public class BehavioralFeatures
    {
        public long Timestamp { get; set; }
        public int KeystrokeCounter { get; set; }
        public int EraseKeysCounter { get; set; }
        public double EraseKeysPercentage { get; set; }
        public double PressPressAverageInterval { get; set; }
        public double PressPressStddevInterval { get; set; }
        public double PressReleaseAverageInterval { get; set; }
        public double PressReleaseStddevInterval { get; set; }
        public int WordCounter { get; set; }
        public double WordAverageLength { get; set; }
        public double WordStddevLength { get; set; }
        
        // Word length distributions
        public int WordLength1 { get; set; }
        public int WordLength2 { get; set; }
        public int WordLength3 { get; set; }
        public int WordLength4 { get; set; }
        public int WordLength5 { get; set; }
        public int WordLength6 { get; set; }
        public int WordLength7 { get; set; }
        public int WordLength8 { get; set; }
        public int WordLength9 { get; set; }
        public int WordLength10 { get; set; }
        public int WordLength11 { get; set; }
        
        // Individual keystroke counters and timing
        public Dictionary<string, int> KeystrokeCounts { get; set; } = new();
        public Dictionary<string, double> PressReleaseAverages { get; set; } = new();
        public Dictionary<string, int> DigraphCounters { get; set; } = new();
        public Dictionary<string, double> DigraphAverageTimes { get; set; } = new();
        
        // Mouse features
        public double[] ClickSpeedAverage { get; set; } = new double[4];
        public double[] ClickSpeedStddev { get; set; } = new double[4];
        public int[] MouseActionCounter { get; set; } = new int[7];
        public int[] MousePositionHistogram { get; set; } = new int[9];
        public int[] MouseMovementDirectionHistogram { get; set; } = new int[8];
        public int[] MouseMovementLengthHistogram { get; set; } = new int[3];
        public double MouseAverageMovementDuration { get; set; }
        public double MouseAverageMovementSpeed { get; set; }
        public double[] MouseAverageMovementSpeedDirection { get; set; } = new double[8];
        
        // Application features
        public int ActiveAppsAverage { get; set; }
        public string CurrentApp { get; set; } = "";
        public string PenultimateApp { get; set; } = "";
        public int ChangesBetweenApps { get; set; }
        public double CurrentAppForegroundTime { get; set; }
        public double CurrentAppAverageProcesses { get; set; }
        public double CurrentAppStddevProcesses { get; set; }
        public double CurrentAppAverageCpu { get; set; }
        public double CurrentAppStddevCpu { get; set; }
        public double SystemAverageCpu { get; set; }
        public double SystemStddevCpu { get; set; }
        public double CurrentAppAverageMem { get; set; }
        public double CurrentAppStddevMem { get; set; }
        public double SystemAverageMem { get; set; }
        public double SystemStddevMem { get; set; }
        
        // Network features
        public long ReceivedBytes { get; set; }
        public long SentBytes { get; set; }
        
        // Identity and compliance
        public string UserId { get; set; } = Environment.UserName;
        public string MachineName { get; set; } = Environment.MachineName;
        public string SignalType { get; set; } = "";
        public string OperatingSystem { get; set; } = Environment.OSVersion.Platform.ToString();
        public string SystemType { get; set; } = GetSystemType();
        public string SystemModel { get; set; } = GetSystemModel();
        public bool VpnConnected { get; set; }
        public bool CorporateVpnUsed { get; set; }
        public bool UntrustedNetworkDetected { get; set; }
        public bool HipaaViolationDetected { get; set; }
        public int VpnConnectionCount { get; set; }
        public bool EncryptionEnabled { get; set; }
        public string EncryptionMethod { get; set; } = "";
        public bool TmpEnabled { get; set; }
        public int EncryptedVolumeCount { get; set; }
        public int UnencryptedVolumeCount { get; set; }
        
        // WiFi features
        public bool WifiConnected { get; set; }
        public string WifiSecurityType { get; set; } = "";
        public bool UnauthorizedNetworkDetected { get; set; }
        public double WifiSignalStrength { get; set; }
        
        // Application Security features
        public bool UnauthorizedAppDetected { get; set; }
        public int UnauthorizedAppCount { get; set; }
        public bool TorrentActivityDetected { get; set; }
        public int TorrentAppCount { get; set; }
        public int UnsignedAppCount { get; set; }
        public int SuspiciousLocationAppCount { get; set; }
        
        // Endpoint Protection features
        public bool EndpointProtectionDisabled { get; set; }
        public int DisabledSecurityServicesCount { get; set; }
        public bool WindowsDefenderDisabled { get; set; }
        public int CriticalSecurityServicesDown { get; set; }
        
        // USB Data Exfiltration features
        public bool SensitiveDataToUSB { get; set; }
        public bool UnauthorizedUSBDetected { get; set; }
        public int USBDataTransferCount { get; set; }
        public int SensitiveFileTransferCount { get; set; }
        public int UnauthorizedStorageDeviceCount { get; set; }
        
        // VPN Bypass features
        public bool UnauthorizedVpnDetected { get; set; }
        public int VpnRejectionCount { get; set; }
        public bool VpnAvoidanceDetected { get; set; }
        public int UnauthorizedVpnAppCount { get; set; }
        public bool ThirdPartyVpnUsage { get; set; }
        
        // Password Security features
        public bool WeakPasswordDetected { get; set; }
        public bool BruteForceDetected { get; set; }
        public int FailedLoginAttempts { get; set; }
        public bool PasswordPolicyViolation { get; set; }
        public int WeakPasswordPatternCount { get; set; }
        
        // Geolocation Security features
        public bool HighRiskGeolocationDetected { get; set; }
        public bool ImpossibleTravelDetected { get; set; }
        public bool AnonymizingServiceDetected { get; set; }
        public int GeolocationRiskScore { get; set; }
        public int HighRiskAuthAttempts { get; set; }
        
        // Hotspot Security features
        public bool UnauthorizedHotspotDetected { get; set; }
        public bool TetheringDetected { get; set; }
        public bool InternetConnectionSharingActive { get; set; }
        public bool NetworkBridgingDetected { get; set; }
        public int HotspotConnectedDevices { get; set; }
        
        // Screen Lock Security features
        public bool ScreenLockPolicyViolation { get; set; }
        public bool ScreensaverDisabled { get; set; }
        public bool ExtendedIdleSession { get; set; }
        public bool UnlockedTooLong { get; set; }
        public int IdleTimeMinutes { get; set; }
        
        // Session Timeout Security features
        public bool SessionTimeoutViolation { get; set; }
        public bool LongRunningSession { get; set; }
        public int IdleApplicationCount { get; set; }
        public int MaxSessionIdleMinutes { get; set; }
        public bool RequiresReauthentication { get; set; }
        
        // Password Length Security features
        public bool PasswordLengthViolation { get; set; }
        public bool GroupPolicyViolation { get; set; }
        public int CurrentMinPasswordLength { get; set; }
        public bool BruteForceOnWeakPasswords { get; set; }
        public int PasswordChangeEvents { get; set; }
        
        // MFA Security features
        public bool SuspiciousMfaRejected { get; set; }
        public bool MfaFatigueAttackDetected { get; set; }
        public bool UnauthorizedMfaAppDetected { get; set; }
        public int MfaPromptRejectionCount { get; set; }
        public int OffHoursMfaAttempts { get; set; }
        
        // Password Expiration features
        public bool PasswordExpired { get; set; }
        public bool PasswordExpirationWarning { get; set; }
        public int DaysSincePasswordChange { get; set; }
        public bool PasswordChangeOverdue { get; set; }
        public int PasswordExpirationEvents { get; set; }
        
        // Unauthorized Software Installation features
        public bool UnsignedSoftwareInstalled { get; set; }
        public bool ExternalRepositoryUsed { get; set; }
        public int UnapprovedPackageCount { get; set; }
        public bool DigitalSignatureViolation { get; set; }
        public bool CorporatePolicyBypass { get; set; }
        public int UnauthorizedRepositoryCount { get; set; }
        
        // Automated Update Compliance features
        public bool AutomaticUpdatesDisabled { get; set; }
        public bool MissedScheduledUpdates { get; set; }
        public int DaysWithoutSecurityUpdates { get; set; }
        public int CriticalPatchesPending { get; set; }
        public bool UpdateServiceFailure { get; set; }
        public bool OutdatedSoftwareDetected { get; set; }
        
        // Unauthorized Data Sharing features
        public bool PersonalEmailSharingDetected { get; set; }
        public bool UnauthorizedCloudUpload { get; set; }
        public bool PublicFileSharingUsed { get; set; }
        public int UnapprovedDataTransmissionCount { get; set; }
        public bool DlpPolicyViolation { get; set; }
        public int SensitiveDataExfiltrationAttempts { get; set; }
        
        // Unauthorized Cloud Storage features
        public bool PersonalCloudStorageUsed { get; set; }
        public bool UnapprovedCloudServiceDetected { get; set; }
        public bool UnencryptedCloudStorageAccess { get; set; }
        public int PersonalCloudSyncCount { get; set; }
        public int UnapprovedCloudUploadCount { get; set; }
        public bool CloudStoragePolicyViolation { get; set; }
        
        // Bluetooth features
        public bool BluetoothEnabled { get; set; }
        public int BluetoothDeviceCount { get; set; }
        public bool UnauthorizedBluetoothDevice { get; set; }

        public static string CsvHeader
        {
            get
            {
                var header = new StringBuilder();
                header.Append("timestamp,keystroke_counter,erase_keys_counter,erase_keys_percentage,");
                header.Append("press_press_average_interval,press_press_stddev_interval,");
                header.Append("press_release_average_interval,press_release_stddev_interval,");
                header.Append("word_counter,word_average_length,word_stddev_length,");
                
                // Word length distributions
                for (int i = 1; i <= 11; i++)
                    header.Append($"word_length_{i},");
                
                // Individual keystroke counters
                var keys = GetAllKeys();
                foreach (var key in keys)
                    header.Append($"keystrokes_key_{key},");
                
                // Press-release averages for each key
                foreach (var key in keys)
                    header.Append($"press_release_average_{key},");
                
                // Digraph counters
                foreach (var key1 in keys)
                    foreach (var key2 in keys)
                        header.Append($"digraph_counter_{key1}{key2},");
                
                // Digraph average times
                foreach (var key1 in keys)
                    foreach (var key2 in keys)
                        header.Append($"digraph_average_time_{key1}{key2},");
                
                // Mouse features
                for (int i = 0; i < 4; i++)
                    header.Append($"click_speed_average_{i},");
                for (int i = 0; i < 4; i++)
                    header.Append($"click_speed_stddev_{i},");
                for (int i = 0; i < 7; i++)
                    header.Append($"mouse_action_counter_{i},");
                for (int i = 1; i <= 9; i++)
                    header.Append($"mouse_position_histogram_{i},");
                for (int i = 1; i <= 8; i++)
                    header.Append($"mouse_movement_direction_histogram_{i},");
                for (int i = 1; i <= 3; i++)
                    header.Append($"mouse_movement_length_histogram_{i},");
                
                header.Append("mouse_average_movement_duration,mouse_average_movement_speed,");
                for (int i = 1; i <= 8; i++)
                    header.Append($"mouse_average_movement_speed_direction_{i},");
                
                // Application and system features
                header.Append("active_apps_average,current_app,penultimate_app,changes_between_apps,");
                header.Append("current_app_foreground_time,current_app_average_processes,current_app_stddev_processes,");
                header.Append("current_app_average_cpu,current_app_stddev_cpu,system_average_cpu,system_stddev_cpu,");
                header.Append("current_app_average_mem,current_app_stddev_mem,system_average_mem,system_stddev_mem,");
                header.Append("received_bytes,sent_bytes,");
                header.Append("vpn_connected,corporate_vpn_used,untrusted_network_detected,hipaa_violation_detected,vpn_connection_count,");
                header.Append("encryption_enabled,encryption_method,tmp_enabled,encrypted_volume_count,unencrypted_volume_count,");
                header.Append("wifi_connected,wifi_security_type,unauthorized_network_detected,wifi_signal_strength,");
                header.Append("unauthorized_app_detected,unauthorized_app_count,torrent_activity_detected,torrent_app_count,unsigned_app_count,suspicious_location_app_count,");
                header.Append("endpoint_protection_disabled,disabled_security_services_count,windows_defender_disabled,critical_security_services_down,");
                header.Append("sensitive_data_to_usb,unauthorized_usb_detected,usb_data_transfer_count,sensitive_file_transfer_count,unauthorized_storage_device_count,");
                header.Append("unauthorized_vpn_detected,vpn_rejection_count,vpn_avoidance_detected,unauthorized_vpn_app_count,third_party_vpn_usage,");
                header.Append("weak_password_detected,brute_force_detected,failed_login_attempts,password_policy_violation,weak_password_pattern_count,");
                header.Append("high_risk_geolocation_detected,impossible_travel_detected,anonymizing_service_detected,geolocation_risk_score,high_risk_auth_attempts,");
                header.Append("unauthorized_hotspot_detected,tethering_detected,internet_connection_sharing_active,network_bridging_detected,hotspot_connected_devices,");
                header.Append("screen_lock_policy_violation,screensaver_disabled,extended_idle_session,unlocked_too_long,idle_time_minutes,");
                header.Append("session_timeout_violation,long_running_session,idle_application_count,max_session_idle_minutes,requires_reauthentication,");
                header.Append("password_length_violation,group_policy_violation,current_min_password_length,brute_force_on_weak_passwords,password_change_events,");
                header.Append("suspicious_mfa_rejected,mfa_fatigue_attack_detected,unauthorized_mfa_app_detected,mfa_prompt_rejection_count,off_hours_mfa_attempts,");
                header.Append("password_expired,password_expiration_warning,days_since_password_change,password_change_overdue,password_expiration_events,");
                header.Append("unsigned_software_installed,external_repository_used,unapproved_package_count,digital_signature_violation,corporate_policy_bypass,unauthorized_repository_count,");
                header.Append("automatic_updates_disabled,missed_scheduled_updates,days_without_security_updates,critical_patches_pending,update_service_failure,outdated_software_detected,");
                header.Append("personal_email_sharing_detected,unauthorized_cloud_upload,public_file_sharing_used,unapproved_data_transmission_count,dlp_policy_violation,sensitive_data_exfiltration_attempts,");
                header.Append("personal_cloud_storage_used,unapproved_cloud_service_detected,unencrypted_cloud_storage_access,personal_cloud_sync_count,unapproved_cloud_upload_count,cloud_storage_policy_violation,");
                header.Append("bluetooth_enabled,bluetooth_device_count,unauthorized_bluetooth_device,");
                header.Append("signal_type,operating_system,system_type,system_model,USER");
                
                return header.ToString();
            }
        }

        public string ToCsvRow()
        {
            var row = new StringBuilder();
            row.Append($"{Timestamp},{KeystrokeCounter},{EraseKeysCounter},{EraseKeysPercentage:F2},");
            row.Append($"{PressPressAverageInterval:F2},{PressPressStddevInterval:F2},");
            row.Append($"{PressReleaseAverageInterval:F2},{PressReleaseStddevInterval:F2},");
            row.Append($"{WordCounter},{WordAverageLength:F2},{WordStddevLength:F2},");
            
            // Word length distributions
            row.Append($"{WordLength1},{WordLength2},{WordLength3},{WordLength4},{WordLength5},");
            row.Append($"{WordLength6},{WordLength7},{WordLength8},{WordLength9},{WordLength10},{WordLength11},");
            
            // Individual keystroke counters
            var keys = GetAllKeys();
            foreach (var key in keys)
                row.Append($"{KeystrokeCounts.GetValueOrDefault(key, 0)},");
            
            // Press-release averages for each key
            foreach (var key in keys)
                row.Append($"{PressReleaseAverages.GetValueOrDefault(key, 0):F2},");
            
            // Digraph counters
            foreach (var key1 in keys)
                foreach (var key2 in keys)
                    row.Append($"{DigraphCounters.GetValueOrDefault($"{key1}{key2}", 0)},");
            
            // Digraph average times
            foreach (var key1 in keys)
                foreach (var key2 in keys)
                    row.Append($"{DigraphAverageTimes.GetValueOrDefault($"{key1}{key2}", 0):F2},");
            
            // Mouse features
            for (int i = 0; i < 4; i++)
                row.Append($"{ClickSpeedAverage[i]:F2},");
            for (int i = 0; i < 4; i++)
                row.Append($"{ClickSpeedStddev[i]:F2},");
            for (int i = 0; i < 7; i++)
                row.Append($"{MouseActionCounter[i]},");
            for (int i = 0; i < 9; i++)
                row.Append($"{MousePositionHistogram[i]},");
            for (int i = 0; i < 8; i++)
                row.Append($"{MouseMovementDirectionHistogram[i]},");
            for (int i = 0; i < 3; i++)
                row.Append($"{MouseMovementLengthHistogram[i]},");
            
            row.Append($"{MouseAverageMovementDuration:F2},{MouseAverageMovementSpeed:F2},");
            for (int i = 0; i < 8; i++)
                row.Append($"{MouseAverageMovementSpeedDirection[i]:F2},");
            
            // Application and system features
            row.Append($"{ActiveAppsAverage},{CurrentApp},{PenultimateApp},{ChangesBetweenApps},");
            row.Append($"{CurrentAppForegroundTime:F2},{CurrentAppAverageProcesses:F2},{CurrentAppStddevProcesses:F2},");
            row.Append($"{CurrentAppAverageCpu:F2},{CurrentAppStddevCpu:F2},{SystemAverageCpu:F2},{SystemStddevCpu:F2},");
            row.Append($"{CurrentAppAverageMem:F2},{CurrentAppStddevMem:F2},{SystemAverageMem:F2},{SystemStddevMem:F2},");
            row.Append($"{ReceivedBytes},{SentBytes},");
            row.Append($"{VpnConnected},{CorporateVpnUsed},{UntrustedNetworkDetected},{HipaaViolationDetected},{VpnConnectionCount},");
            row.Append($"{EncryptionEnabled},{EncryptionMethod},{TmpEnabled},{EncryptedVolumeCount},{UnencryptedVolumeCount},");
            row.Append($"{WifiConnected},{WifiSecurityType},{UnauthorizedNetworkDetected},{WifiSignalStrength:F2},");
            row.Append($"{UnauthorizedAppDetected},{UnauthorizedAppCount},{TorrentActivityDetected},{TorrentAppCount},{UnsignedAppCount},{SuspiciousLocationAppCount},");
            row.Append($"{EndpointProtectionDisabled},{DisabledSecurityServicesCount},{WindowsDefenderDisabled},{CriticalSecurityServicesDown},");
            row.Append($"{SensitiveDataToUSB},{UnauthorizedUSBDetected},{USBDataTransferCount},{SensitiveFileTransferCount},{UnauthorizedStorageDeviceCount},");
            row.Append($"{UnauthorizedVpnDetected},{VpnRejectionCount},{VpnAvoidanceDetected},{UnauthorizedVpnAppCount},{ThirdPartyVpnUsage},");
            row.Append($"{WeakPasswordDetected},{BruteForceDetected},{FailedLoginAttempts},{PasswordPolicyViolation},{WeakPasswordPatternCount},");
            row.Append($"{HighRiskGeolocationDetected},{ImpossibleTravelDetected},{AnonymizingServiceDetected},{GeolocationRiskScore},{HighRiskAuthAttempts},");
            row.Append($"{UnauthorizedHotspotDetected},{TetheringDetected},{InternetConnectionSharingActive},{NetworkBridgingDetected},{HotspotConnectedDevices},");
            row.Append($"{ScreenLockPolicyViolation},{ScreensaverDisabled},{ExtendedIdleSession},{UnlockedTooLong},{IdleTimeMinutes},");
            row.Append($"{SessionTimeoutViolation},{LongRunningSession},{IdleApplicationCount},{MaxSessionIdleMinutes},{RequiresReauthentication},");
            row.Append($"{PasswordLengthViolation},{GroupPolicyViolation},{CurrentMinPasswordLength},{BruteForceOnWeakPasswords},{PasswordChangeEvents},");
            row.Append($"{SuspiciousMfaRejected},{MfaFatigueAttackDetected},{UnauthorizedMfaAppDetected},{MfaPromptRejectionCount},{OffHoursMfaAttempts},");
            row.Append($"{PasswordExpired},{PasswordExpirationWarning},{DaysSincePasswordChange},{PasswordChangeOverdue},{PasswordExpirationEvents},");
            row.Append($"{UnsignedSoftwareInstalled},{ExternalRepositoryUsed},{UnapprovedPackageCount},{DigitalSignatureViolation},{CorporatePolicyBypass},{UnauthorizedRepositoryCount},");
            row.Append($"{AutomaticUpdatesDisabled},{MissedScheduledUpdates},{DaysWithoutSecurityUpdates},{CriticalPatchesPending},{UpdateServiceFailure},{OutdatedSoftwareDetected},");
            row.Append($"{PersonalEmailSharingDetected},{UnauthorizedCloudUpload},{PublicFileSharingUsed},{UnapprovedDataTransmissionCount},{DlpPolicyViolation},{SensitiveDataExfiltrationAttempts},");
            row.Append($"{PersonalCloudStorageUsed},{UnapprovedCloudServiceDetected},{UnencryptedCloudStorageAccess},{PersonalCloudSyncCount},{UnapprovedCloudUploadCount},{CloudStoragePolicyViolation},");
            row.Append($"{BluetoothEnabled},{BluetoothDeviceCount},{UnauthorizedBluetoothDevice},");
            row.Append($"{SignalType},{OperatingSystem},{SystemType},{SystemModel},{UserId}");
            
            return row.ToString();
        }
        
        private static List<string> GetAllKeys()
        {
            return new List<string>
            {
                "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
                "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
                "n", "ñ", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
                "´", "`", "\"", "ç", "^", "º", "@", "$", "%", "&", "/", "(", ")", "=", "|",
                "leftwindows", "shift", "capslock", "tab", "ª", "\\", "#", "esc",
                "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10", "f11", "f12",
                "PrtSc", "insert", "delete", "home", "ind", "pageup", "pagedown", "numlock",
                "}", "{", "-", "_", ".", "[", "]", "*", "<", ">",
                "space", "inter", "rightctrl", "rightshift", "backspace", "alt",
                "left", "right", "up", "down", "rightarrow", "leftarrow", "uparrow", "downarrow", "+"
            };
        }
        
        private static string GetSystemType()
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                try
                {
                    using var searcher = new ManagementObjectSearcher("SELECT Architecture FROM Win32_Processor");
                    foreach (ManagementObject obj in searcher.Get())
                        return obj["Architecture"]?.ToString() switch
                        {
                            "0" => "x86",
                            "9" => "x64",
                            "12" => "ARM64",
                            _ => Environment.Is64BitOperatingSystem ? "x64" : "x86"
                        };
                }
                catch { }
            }
            else if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                try
                {
                    var process = new System.Diagnostics.Process
                    {
                        StartInfo = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "uname",
                            Arguments = "-m",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    process.Start();
                    var output = process.StandardOutput.ReadToEnd().Trim();
                    process.WaitForExit();
                    return output switch
                    {
                        "x86_64" => "x64",
                        "arm64" => "ARM64",
                        "i386" => "x86",
                        _ => Environment.Is64BitOperatingSystem ? "x64" : "x86"
                    };
                }
                catch { }
            }
            else if (File.Exists("/proc/cpuinfo"))
            {
                try
                {
                    var cpuInfo = File.ReadAllText("/proc/cpuinfo");
                    if (cpuInfo.Contains("aarch64") || cpuInfo.Contains("arm64"))
                        return "ARM64";
                    if (cpuInfo.Contains("x86_64"))
                        return "x64";
                    if (cpuInfo.Contains("i386") || cpuInfo.Contains("i686"))
                        return "x86";
                }
                catch { }
            }
            return Environment.Is64BitOperatingSystem ? "x64" : "x86";
        }
        
        private static string GetSystemModel()
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                try
                {
                    using var searcher = new ManagementObjectSearcher("SELECT Manufacturer, Model FROM Win32_ComputerSystem");
                    foreach (ManagementObject obj in searcher.Get())
                        return $"{obj["Manufacturer"]} {obj["Model"]}";
                }
                catch { }
            }
            else if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                try
                {
                    var process = new System.Diagnostics.Process
                    {
                        StartInfo = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "/bin/bash",
                            Arguments = "-c \"system_profiler SPHardwareDataType | grep 'Model Name' | cut -d: -f2 | xargs\"",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    process.Start();
                    var output = process.StandardOutput.ReadToEnd().Trim();
                    process.WaitForExit();
                    return !string.IsNullOrWhiteSpace(output) ? output : "Mac";
                }
                catch { }
            }
            else if (File.Exists("/proc/cpuinfo"))
            {
                try
                {
                    var cpuInfo = File.ReadAllText("/proc/cpuinfo");
                    var modelLine = cpuInfo.Split('\n').FirstOrDefault(l => l.StartsWith("model name"));
                    if (modelLine != null)
                    {
                        var model = modelLine.Split(':')[1].Trim();
                        return !string.IsNullOrWhiteSpace(model) ? model : "Linux System";
                    }
                }
                catch { }
            }
            return Environment.ProcessorCount + "-Core System";
        }
    }
}