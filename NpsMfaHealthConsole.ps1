<#
.SYNOPSIS
    NPS + Azure MFA Extension Health Console & Troubleshooter.
    
.DESCRIPTION
    A comprehensive GUI-based tool to troubleshoot, manage, and audit the Azure MFA NPS Extension.
    It parses NPS text logs, correlates them with Azure MFA Event logs, manages certificates,
    and handles registry configuration.

.NOTES
    Run as Administrator.
    Requires: Windows Server with NPS and Azure MFA Extension.
    Compabitility: Windows PowerShell 5.1 and PowerShell 7+
#>

param(
    [string]$DefaultLogPath = "$env:SystemRoot\System32\LogFiles",
    [string]$OutputPath = "C:\NPS_AzureMFA_Collect"
)

# Load required assemblies for WPF
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ==============================================================================
#  GLOBAL VARIABLES & CONFIG
# ==============================================================================
$Global:MfaRegPath = "HKLM:\SOFTWARE\Microsoft\AzureMfa"
$Global:NpsService = "IAS" # IAS is the service name for NPS
$Global:MfaDefScript = "C:\Program Files\Microsoft\AzureMfa\Config\AzureMfaNpsExtnConfigSetup.ps1"

# Definition of Known Troubleshooting Keys
$Global:KnownRegKeys = @(
    @{ 
        Name = "OVERRIDE_NUMBER_MATCHING_WITH_OTP"; 
        Type = "String"; 
        Options = @("TRUE", "FALSE"); 
        Desc = "Fixes 'Radius dropped' errors for VPNs/Gateways that do not support displaying the Number Match code. Forces OTP input instead." 
    },
    @{ 
        Name = "REQUIRE_USER_MATCH"; 
        Type = "String"; 
        Options = @("TRUE", "FALSE"); 
        Desc = "Enforces strict matching between the RADIUS username and the Azure AD UPN. Set FALSE if users log in with SAMAccountName but UPN differs." 
    },
    @{ 
        Name = "OVERRIDE_USER_LOCKOUT"; 
        Type = "String"; 
        Options = @("TRUE", "FALSE"); 
        Desc = "If TRUE, allows Azure MFA processing even if the user account is locked in Active Directory." 
    },
    @{ 
        Name = "ExtensionTimeOut"; 
        Type = "DWORD"; 
        Options = @("60000", "30000", "120000"); # 60s default
        Desc = "Max time (ms) NPS waits for MFA response. Increase to 60000 (60s) or 120000 (2m) if users get 'Discard' errors while approving phone prompts." 
    },
    @{ 
        Name = "UserIdentityAttribute"; 
        Type = "String"; 
        Options = @("userPrincipalName", "mail", "sAMAccountName", "objectSid"); 
        Desc = "The AD attribute used to match the Azure AD User. Default is userPrincipalName. Change if your on-prem UPNs don't match Cloud UPNs." 
    },
    @{ 
        Name = "IpWhitelist"; 
        Type = "String"; 
        Options = @("Enter IPs..."); 
        Desc = "Comma-separated list of IPs to bypass MFA. (Modern setups usually prefer Conditional Access policies)." 
    },
    @{ 
        Name = "EnableAudit"; 
        Type = "String"; 
        Options = @("TRUE", "FALSE"); 
        Desc = "Enables detailed auditing traces for the extension. Useful for deep debugging with Microsoft Support." 
    },
    @{ 
        Name = "MaxConcurrentRequests"; 
        Type = "DWORD"; 
        Options = @("50", "100", "200"); 
        Desc = "Tuning parameter for high-load servers. Default is usually sufficient." 
    }
)

# ==============================================================================
#  BACKEND FUNCTIONS (LOGIC)
# ==============================================================================

function Write-Status {
    param($Message)
    if ($Global:StatusBlock) {
        $Global:StatusBlock.Text = "$(Get-Date -Format 'HH:mm:ss') - $Message"
        [System.Windows.Forms.Application]::DoEvents()
    } else {
        Write-Host $Message
    }
}

function Test-TcpConnection {
    param($Hostname, $Port)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($Hostname, $Port, $null, $null)
        $success = $connect.AsyncWaitHandle.WaitOne(2000, $true) # 2 sec timeout
        $tcp.Close()
        return $success
    } catch {
        return $false
    }
}

function Test-NpsMfaPrerequisites {
    $results = @()
    
    # 1. Check NPS Service Status & Startup & Account
    $npsName = $Global:NpsService
    $nps = Get-Service -Name $npsName -ErrorAction SilentlyContinue
    
    if ($nps) {
        $statusStr = "$($nps.Status)"
        if ($nps.StartType -ne 'Automatic') { $statusStr += " (Startup: $($nps.StartType))" }
        
        # Get Logon Account (Important for Cert Access)
        try {
            $wmi = Get-WmiObject Win32_Service -Filter "Name='$npsName'" -ErrorAction Stop
            $account = $wmi.StartName
            $statusStr += " [Logon: $account]"
        } catch {
            $account = "Unknown"
        }

        $results += [PSCustomObject]@{
            Check = "NPS Service Status"
            Status = if ($nps.Status -eq 'Running') { "OK" } else { "Stopped/Issue" }
            Details = "Service: $npsName ($statusStr)"
        }
    } else {
        $results += [PSCustomObject]@{ Check="NPS Service Status"; Status="Missing"; Details="IAS Service not found" }
    }

    # 2. Check Extension Registry
    $reg = Test-Path $Global:MfaRegPath
    $results += [PSCustomObject]@{
        Check = "Azure MFA Registry"
        Status = if ($reg) { "OK" } else { "Missing" }
        Details = $Global:MfaRegPath
    }

    # 3. Check DLLs & Version (Improved for Newer Versions)
    # Define potential paths for the extension DLL
    $pathsToCheck = @(
        "C:\Program Files\Microsoft\AzureMfa\Nps\AzureMfaNpsExt.dll",       # Classic Path
        "C:\Program Files\Microsoft\AzureMfa\Extensions\MfaNpsAuthnExt.dll" # Newer Path
    )
    
    $foundDll = $null
    
    foreach ($path in $pathsToCheck) {
        if (Test-Path $path) {
            $foundDll = $path
            break
        }
    }
    
    if ($foundDll) {
        $verInfo = (Get-Item $foundDll).VersionInfo
        $ver = $verInfo.ProductVersion
        $results += [PSCustomObject]@{
            Check = "Azure MFA Extension"
            Status = "OK"
            Details = "Installed v$ver ($foundDll)"
        }
    } else {
        # Detailed failure logic
        $baseFolder = "C:\Program Files\Microsoft\AzureMfa"
        if (Test-Path "$baseFolder\Extensions") {
             $results += [PSCustomObject]@{
                Check = "Azure MFA Extension"
                Status = "Warning"
                Details = "Folder 'Extensions' found but 'MfaNpsAuthnExt.dll' is missing."
            }
        } elseif (Test-Path "$baseFolder\Nps") {
             $results += [PSCustomObject]@{
                Check = "Azure MFA Extension"
                Status = "Warning"
                Details = "Folder 'Nps' found but 'AzureMfaNpsExt.dll' is missing."
            }
        } else {
            $results += [PSCustomObject]@{
                Check = "Azure MFA Extension"
                Status = "Critical"
                Details = "Installation folders not found in $baseFolder"
            }
        }
    }

    # 4. Check Connectivity to Azure (Critical for MFA)
    $azureHost = "adnotifications.windowsazure.com"
    $canConnect = Test-TcpConnection -Hostname $azureHost -Port 443
    $results += [PSCustomObject]@{
        Check = "Azure Connectivity"
        Status = if ($canConnect) { "OK" } else { "Failed" }
        Details = "TCP 443 to $azureHost"
    }

    # 5. Check Certificate Validity (Quick Audit)
    $certs = Get-MfaCerts
    $validCert = $certs | Where-Object { $_.Status -eq "Valid" -and $_.IsMfaCandidate } | Select-Object -First 1
    
    $certMsg = "No valid active cert found in LocalMachine\My"
    $certStatus = "Expired/Missing"
    
    if ($validCert) {
        $certStatus = "OK"
        # Extract TenantID from Subject (CN=...)
        $subj = $validCert.Subject
        if ($subj -match "CN=([0-9a-fA-F-]{36})") {
            $tid = $matches[1]
            $certMsg = "Valid (Exp: $($validCert.NotAfter.ToString('yyyy-MM-dd'))) Tenant: $tid"
        } else {
            $certMsg = "Valid (Exp: $($validCert.NotAfter.ToString('yyyy-MM-dd'))) Subject: $subj"
        }
    }

    $results += [PSCustomObject]@{
        Check = "Azure MFA Certificate"
        Status = $certStatus
        Details = $certMsg
    }
    
    # 6. Check Radius Clients (Config)
    try {
        if (Get-Command Get-NpsRadiusClient -ErrorAction SilentlyContinue) {
            $clients = Get-NpsRadiusClient -ErrorAction Stop
            $clientArray = @($clients)
            $cnt = $clientArray.Count
            
            # Extract names for display
            $clientNames = ($clientArray | Select-Object -ExpandProperty Name) -join ", "
            
            $results += [PSCustomObject]@{
                Check = "NPS Radius Clients"
                Status = if ($cnt -gt 0) { "OK" } else { "Warning" }
                Details = "$cnt configured: $clientNames"
            }
        } else {
             $results += [PSCustomObject]@{ Check="NPS Radius Clients"; Status="Info"; Details="NPS Module not loaded" }
        }
    } catch {
         $results += [PSCustomObject]@{ Check="NPS Radius Clients"; Status="Error"; Details="Failed to query clients" }
    }

    return $results
}

function Get-NpsLogFiles {
    param($Path)
    # Recursively find IN*.log files
    if (Test-Path $Path) {
        return Get-ChildItem -Path $Path -Filter "IN*.log" -Recurse | Sort-Object LastWriteTime -Descending
    }
    return $null
}

function Parse-NpsLogs {
    param(
        [string]$UserName,
        [int]$Last = 50
    )

    Write-Status "Locating NPS logs..."
    $logFiles = Get-NpsLogFiles -Path $DefaultLogPath
    
    if (-not $logFiles) {
        Write-Status "No NPS logs found in $DefaultLogPath"
        return @()
    }

    # Use the most recent log file
    $latestLog = $logFiles[0]
    Write-Status "Parsing $($latestLog.FullName)..."

    # Copy to temp to avoid locking issues
    $tempFile = "$env:TEMP\NPS_Analysis_$(Get-Random).log"
    Copy-Item $latestLog.FullName -Destination $tempFile -Force

    $parsedEntries = @()

    try {
        # Read file, assume IAS format (skip header lines starting with # except the last one which is the header)
        $lines = Get-Content $tempFile
        $headerLine = $lines | Where-Object { $_ -like "ComputerName,*" } | Select-Object -Last 1
        
        if (-not $headerLine) {
            # Fallback for standard DTS complient header if simplified header not found
            $headerLine = "ComputerName,ServiceName,Record-Date,Record-Time,Packet-Type,User-Name,Fully-Qualifed-User-Name,Called-Station-Id,Calling-Station-Id,Callback-Number,Framed-IP-Address,NAS-Identifier,NAS-IP-Address,NAS-Port,Client-Vendor,Client-IP-Address,Client-Friendly-Name,Event-Timestamp,Port-Limit,NAS-Port-Type,Connect-Info,Framed-Protocol,Service-Type,Authentication-Type,Policy-Name,Reason-Code,Class,Session-Timeout,Idle-Timeout,Termination-Action,EAP-Friendly-Name,Acct-Status-Type,Acct-Delay-Time,Acct-Input-Octets,Acct-Output-Octets,Acct-Session-Id,Acct-Authentic,Acct-Session-Time,Acct-Input-Packets,Acct-Output-Packets,Acct-Terminate-Cause,Acct-Multi-Session-Id,Acct-Link-Count,Acct-Interim-Interval,Tunnel-Type,Tunnel-Medium-Type,Tunnel-Client-Endpt,Tunnel-Server-Endpt,Acct-Event-Guest,Ring-Algorithm,Ring-Duration,Ring-Session-Id,Ring-Data-Count,Ring-Data-Type,Ring-Data"
        }

        $headers = $headerLine -split ','
        
        # Get Data lines (not starting with ComputerName and not empty)
        $dataLines = $lines | Where-Object { $_ -ne "" -and $_ -notmatch "^ComputerName" }

        foreach ($line in $dataLines) {
            $cols = $line -split ','
            
            # Basic Bounds checking
            if ($cols.Count -lt 5) { continue }

            $obj = [PSCustomObject]@{ }
            
            # Map common fields based on standard IAS ordering or best guess
            # Creating a robust mapping is hard without XML config, assuming standard:
            # 0=Computer, 1=Service, 2=Date, 3=Time, 4=PacketType, 5=User...
            
            # Helper to safely get index
            $val = { param($idx) if ($idx -lt $cols.Count) { $cols[$idx] } else { $null } }

            $pTypeMap = @{ '1'='Request'; '2'='Accept'; '3'='Reject'; '4'='Accounting'; '11'='Challenge' }
            $pType = &$val 4
            
            # Optimization: Only process Requests, Challenges, Accepts, Rejects
            if ($pType -notin '1','2','3','11') { continue }

            $uName = &$val 5
            
            # Filter by User if provided
            if (![string]::IsNullOrWhiteSpace($UserName) -and $uName -notlike "*$UserName*") { continue }

            # Safe lookup for PS 5.1 compatibility (replaced ??)
            $pTypeLabel = if ($pTypeMap.ContainsKey($pType)) { $pTypeMap[$pType] } else { "Unknown($pType)" }

            $obj | Add-Member -MemberType NoteProperty -Name "Timestamp" -Value ("{0} {1}" -f (&$val 2), (&$val 3))
            $obj | Add-Member -MemberType NoteProperty -Name "PacketType" -Value $pTypeLabel
            $obj | Add-Member -MemberType NoteProperty -Name "User" -Value $uName
            $obj | Add-Member -MemberType NoteProperty -Name "ClientIP" -Value (&$val 15) # Approx index
            $obj | Add-Member -MemberType NoteProperty -Name "Policy" -Value (&$val 24)   # Approx index
            $obj | Add-Member -MemberType NoteProperty -Name "ReasonCode" -Value (&$val 25) # Approx index
            $obj | Add-Member -MemberType NoteProperty -Name "Raw" -Value $line

            $parsedEntries += $obj
        }
    }
    catch {
        Write-Warning "Error parsing logs: $_"
    }
    finally {
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
    }

    # Sort and take last N
    return $parsedEntries | Sort-Object Timestamp | Select-Object -Last $Last
}

function Get-WinEvtBatch {
    param($LogName, $Provider, $Id, $Time, $User)
    
    $filter = @{ LogName = $LogName; StartTime = $Time }
    if ($Provider) { $filter.Add("ProviderName", $Provider) }
    if ($Id) { $filter.Add("Id", $Id) }
    
    $results = @()
    try {
        $evts = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
        foreach ($e in $evts) {
            # Optional User Filter
            if (-not [string]::IsNullOrWhiteSpace($User)) {
                if ($e.Message -notmatch $User) { continue }
            }
            $results += $e
        }
    } catch { 
        # No events found is normal
    }
    return $results
}

function Get-AzureMfaLogEntries {
    param($UserName, $StartTime)
    
    Write-Status "Querying Azure MFA Event Logs..."
    $results = @()
    
    # Check both AuthN and AuthZ logs
    $logNames = @("Microsoft-AzureMFA-AuthN/AuthNOptCh", "Microsoft-AzureMFA-AuthZ/AuthZOptCh")
    
    foreach ($log in $logNames) {
        $evts = Get-WinEvtBatch -LogName $log -Time $StartTime -User $UserName
        foreach ($e in $evts) {
            $status = "Info"
            if ($e.Message -match "Challenge requested") { $status = "Challenge Sent" }
            elseif ($e.Message -match "Access Accepted") { $status = "MFA Success" }
            elseif ($e.Message -match "Access Denied") { $status = "MFA Denied" }
            
            $results += [PSCustomObject]@{
                Timestamp = $e.TimeCreated
                Source    = "AzureMFA"
                Details   = "$status (ID: $($e.Id))"
                EventId   = $e.Id
                RawMessage = $e.Message
            }
        }
    }
    return $results
}

function Get-SystemNpsEvents {
    param($UserName, $StartTime)
    
    Write-Status "Querying System Event Logs (NPS/IAS)..."
    # Filter for Provider = NPS or IAS
    # Note: System log usually doesn't have Username in message for service events, so we might skip User filter here 
    # unless we strictly want correlated errors. For now, fetch all recent to show service instability.
    
    $evts = Get-WinEvtBatch -LogName "System" -Provider @("NPS", "IAS") -Time $StartTime
    $results = @()
    
    foreach ($e in $evts) {
        $results += [PSCustomObject]@{
            Timestamp = $e.TimeCreated
            Source    = "WinEvt-System"
            Details   = "Service Event: $($e.LevelDisplayName)"
            EventId   = $e.Id
            RawMessage = $e.Message
        }
    }
    return $results
}

function Get-SecurityNpsEvents {
    param($UserName, $StartTime)
    
    Write-Status "Querying Security Audit Logs..."
    # Event IDs: 6272 (Grant), 6273 (Deny), 6278 (Grant), 6274 (Discard)
    # This requires Audit Policy to be enabled
    
    $evts = Get-WinEvtBatch -LogName "Security" -Id @(6272, 6273, 6274, 6278) -Time $StartTime -User $UserName
    $results = @()
    
    foreach ($e in $evts) {
        $type = "Audit-Info"
        if ($e.Id -eq 6273) { $type = "Audit-Failure" }
        elseif ($e.Id -eq 6272 -or $e.Id -eq 6278) { $type = "Audit-Success" }
        
        $results += [PSCustomObject]@{
            Timestamp = $e.TimeCreated
            Source    = "WinEvt-Security"
            Details   = "$type (ID: $($e.Id))"
            EventId   = $e.Id
            RawMessage = $e.Message
        }
    }
    return $results
}

function Trace-AuthFlow {
    param($UserName, $LookbackMinutes)
    
    $cutoff = (Get-Date).AddMinutes(-$LookbackMinutes)
    
    # 1. NPS Text Logs
    $npsData = Parse-NpsLogs -UserName $UserName -Last 100
    # Convert String Timestamp to DateTime
    $npsData | ForEach-Object { try { $_.Timestamp = [DateTime]::Parse($_.Timestamp) } catch {} }

    # 2. Azure MFA Logs
    $mfaData = Get-AzureMfaLogEntries -UserName $UserName -StartTime $cutoff
    
    # 3. System Logs (Service Health) - Wide filter (no username) to show context
    $sysData = Get-SystemNpsEvents -StartTime $cutoff
    
    # 4. Security Logs (Audit) - User specific
    $secData = Get-SecurityNpsEvents -UserName $UserName -StartTime $cutoff

    # Normalize NPS Text Objects
    $npsNormalized = $npsData | Select-Object @{N='Timestamp';E={$_.Timestamp}}, @{N='Source';E={'NPS-Text'}}, @{N='Details';E={"$($_.PacketType) (Pol:$($_.Policy) Reason:$($_.ReasonCode))"}}, @{N='EventId';E={0}}, @{N='RawMessage';E={$_.Raw}}

    # Merge All
    $merged = $npsNormalized + $mfaData + $sysData + $secData | Sort-Object Timestamp

    # Heuristic Analysis
    $conclusion = "Waiting for analysis..."
    $rejects = $npsNormalized | Where-Object { $_.Details -match "Reject" }
    $mfaSuccess = $mfaData | Where-Object { $_.Details -match "MFA Success" }
    $mfaChallenge = $mfaData | Where-Object { $_.Details -match "Challenge Sent" }

    if ($rejects) {
        if (-not $mfaData) {
            $conclusion = "FAILURE: NPS Rejected request, and no Azure MFA events were found. Likely failed NPS Policy conditions before reaching MFA."
        }
        elseif ($mfaChallenge -and -not $mfaSuccess) {
            $conclusion = "FAILURE: MFA Challenge sent, but no Success recorded. User likely failed OTP or timed out."
        }
        elseif ($mfaSuccess) {
            $conclusion = "FAILURE: MFA indicated Success, but NPS eventually Rejected. Check NPS Network Policies execution order or Dial-in permissions."
        }
        else {
            $conclusion = "FAILURE: NPS Reject detected with ambiguous MFA activity."
        }
    } else {
        $conclusion = "INFO: No recent Rejects found in the analyzed window."
    }

    return @{
        Timeline = $merged
        Conclusion = $conclusion
    }
}

# ==============================================================================
#  CERTIFICATE LOGIC
# ==============================================================================

function Get-MfaCerts {
    # Logic: Find certs in LocalMachine\My. Azure MFA extension certs usually have the TenantID as subject 
    # OR are issued by specific CAs. Best heuristic: Look for certs associated with the AppId if possible, 
    # but strictly speaking, we check what looks like a Tenant ID guid in Subject.
    
    $certs = Get-ChildItem Cert:\LocalMachine\My
    $results = @()
    $today = Get-Date

    foreach ($c in $certs) {
        # Rudimentary filter: Assuming standard Azure MFA certs created by the PS script
        # Usually self-signed (Issuer = Subject) or have specific KeyUsages. 
        # We will cast a wide net and let user decide, focusing on GUID-like subjects
        
        $isExpired = $c.NotAfter -lt $today
        $daysRem = ($c.NotAfter - $today).Days
        
        $results += [PSCustomObject]@{
            Subject      = $c.Subject
            Issuer       = $c.Issuer
            Thumbprint   = $c.Thumbprint
            NotAfter     = $c.NotAfter
            DaysLeft     = $daysRem
            Status       = if ($isExpired) { "Expired" } else { "Valid" }
            IsMfaCandidate = ($c.Subject -match "CN=[0-9a-fA-F-]{36}") # Looks like Tenant ID
        }
    }
    
    return $results | Sort-Object NotAfter -Descending
}

function Remove-OldMfaCerts {
    param([string[]]$ThumbprintsToRemove)
    
    $log = @()
    foreach ($tp in $ThumbprintsToRemove) {
        try {
            $path = "Cert:\LocalMachine\My\$tp"
            if (Test-Path $path) {
                Remove-Item $path -Force -ErrorAction Stop
                $log += "Deleted $tp"
            }
        } catch {
            $log += "Failed to delete $tp : $_"
        }
    }
    return $log
}

# ==============================================================================
#  REGISTRY LOGIC
# ==============================================================================

function Get-RegSettings {
    $props = Get-ItemProperty $Global:MfaRegPath -ErrorAction SilentlyContinue
    $settings = @()
    
    if ($props) {
        $props.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' } | ForEach-Object {
            $settings += [PSCustomObject]@{
                Key = $_.Name
                Value = $_.Value
                Type = "String/DWord" # Simplified
            }
        }
    } 
    return $settings
}

function Set-RegSetting {
    param($Name, $Value)
    if (-not (Test-Path $Global:MfaRegPath)) {
        New-Item -Path $Global:MfaRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $Global:MfaRegPath -Name $Name -Value $Value
}

# ==============================================================================
#  GUI BUILDER
# ==============================================================================

# XAML Definition
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="NPS + Azure MFA Health Console" Height="600" Width="850" WindowStartupLocation="CenterScreen">
    <Window.Resources>
        <Style TargetType="Button">
            <Setter Property="Margin" Value="5"/>
            <Setter Property="Padding" Value="10,5"/>
            <Setter Property="Background" Value="#DDDDDD"/>
        </Style>
        <Style TargetType="Label">
            <Setter Property="FontWeight" Value="Bold"/>
        </Style>
    </Window.Resources>
    
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/> <!-- Header -->
            <RowDefinition Height="*"/>    <!-- Tabs -->
            <RowDefinition Height="Auto"/> <!-- Status Bar -->
        </Grid.RowDefinitions>

        <TextBlock Text="NPS + Azure MFA Diagnostics" FontSize="20" FontWeight="Bold" Margin="0,0,0,10" Grid.Row="0"/>

        <TabControl Grid.Row="1">
            
            <!-- TAB 1: OVERVIEW -->
            <TabItem Header="Overview">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    
                    <StackPanel Orientation="Horizontal" Grid.Row="0">
                        <Button Name="btnRefreshPrereq" Content="Refresh Health Checks"/>
                    </StackPanel>

                    <DataGrid Name="dgPrereqs" Grid.Row="1" AutoGenerateColumns="True" IsReadOnly="True" Margin="0,10" HeadersVisibility="Column"/>
                    
                    <TextBlock Text="Ensure NPS Service is running and Extension is installed before proceeding." Grid.Row="2" FontStyle="Italic"/>
                </Grid>
            </TabItem>

            <!-- TAB 2: LOGS & CORRELATION -->
            <TabItem Header="Logs &amp; Correlation">
                <Grid Margin="10">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="300"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <!-- Sidebar Controls -->
                    <StackPanel Grid.Column="0" Grid.Row="0" Grid.RowSpan="2" Margin="0,0,10,0">
                        <Label Content="Target User (UPN/SamAccount):"/>
                        <TextBox Name="txtLogUser" Padding="5"/>
                        
                        <Label Content="Lookback (Minutes):"/>
                        <TextBox Name="txtLookback" Text="30" Padding="5"/>

                        <Button Name="btnAnalyze" Content="Analyze Auth Flow" Background="#ADD8E6" FontWeight="Bold"/>
                        
                        <Label Content="Analysis Result:" Margin="0,20,0,5"/>
                        <TextBlock Name="txtConclusion" TextWrapping="Wrap" Foreground="Red" FontWeight="Bold"/>
                    </StackPanel>

                    <!-- Results Grid -->
                    <DataGrid Name="dgTimeline" Grid.Column="1" Grid.Row="0" Grid.RowSpan="2" AutoGenerateColumns="True" IsReadOnly="True" HeadersVisibility="Column"/>
                    
                    <!-- Detail View -->
                    <TextBox Name="txtLogDetail" Grid.Column="0" Grid.ColumnSpan="2" Grid.Row="2" Height="100" 
                             Background="#F0F0F0" Text="Select a row to see details..." Margin="0,10,0,0" Padding="5"
                             TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" IsReadOnly="True"/>
                </Grid>
            </TabItem>

            <!-- TAB 3: CERTIFICATES -->
            <TabItem Header="Certificates">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <StackPanel Orientation="Horizontal" Grid.Row="0">
                        <Button Name="btnScanCerts" Content="Scan Local Store"/>
                        <Button Name="btnRemoveExpired" Content="Remove Selected Expired" Background="#FFB6B6"/>
                        <Button Name="btnLaunchMsScript" Content="Run MS Renewal Script (External)"/>
                    </StackPanel>

                    <DataGrid Name="dgCerts" Grid.Row="1" AutoGenerateColumns="True" IsReadOnly="True" Margin="0,10"/>
                </Grid>
            </TabItem>

            <!-- TAB 4: REGISTRY CONFIG (UPDATED) -->
            <TabItem Header="Registry Config">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <TextBlock Text="Azure MFA Registry Troubleshooting Keys" FontWeight="Bold" FontSize="14" Grid.Row="0" Margin="0,0,0,10"/>
                    
                    <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
                        <StackPanel Name="pnlRegistryKeys">
                           <!-- Dynamic Content Will Be Loaded Here by PowerShell -->
                        </StackPanel>
                    </ScrollViewer>
                    
                    <Border Grid.Row="2" Background="#EEEEEE" Padding="10" Margin="0,10,0,0">
                        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                             <Button Name="btnRefreshReg" Content="Refresh Values"/>
                             <Button Name="btnApplyReg" Content="Apply Configuration" Background="#90EE90" FontWeight="Bold"/>
                        </StackPanel>
                    </Border>
                </Grid>
            </TabItem>
            
            <!-- TAB 5: START FRESH / ADVANCED -->
            <TabItem Header="Start Fresh / Advanced">
                <StackPanel Margin="20">
                    <TextBlock Text="Advanced Troubleshooting &amp; Reset" FontSize="16" FontWeight="Bold" Margin="0,0,0,10"/>
                    
                    <CheckBox Name="chkAck" Content="I have analyzed the logs and confirmed a reset is necessary." Margin="0,10"/>
                    
                    <GroupBox Header="Actions (Requires Checkbox)" Padding="10">
                        <StackPanel>
                            <Button Name="btnBackupConfig" Content="1. Backup NPS Config &amp; Reg Keys" IsEnabled="False"/>
                            <Button Name="btnResetReg" Content="2. Reset Registry Defaults" IsEnabled="False"/>
                            <TextBlock Text="3. For Certificate Reset, use the 'Certificates' tab to remove old ones, then run MS Renewal Script." Margin="5,10" Foreground="Gray"/>
                        </StackPanel>
                    </GroupBox>
                </StackPanel>
            </TabItem>

        </TabControl>

        <!-- Status Bar -->
        <TextBlock Name="txtStatus" Grid.Row="2" Text="Ready" Margin="5"/>
    </Grid>
</Window>
"@

# Read XAML
# FIX for PowerShell 5.1: Convert String to [XML] explicitly before passing to XmlNodeReader
[xml]$xamlXml = $xaml
$reader = (New-Object System.Xml.XmlNodeReader $xamlXml)
$window = [System.Windows.Markup.XamlReader]::Load($reader)

# ==============================================================================
#  CONNECTING GUI ELEMENTS
# ==============================================================================

# -- Elements References --
$btnRefreshPrereq = $window.FindName("btnRefreshPrereq")
$dgPrereqs        = $window.FindName("dgPrereqs")

$txtLogUser       = $window.FindName("txtLogUser")
$txtLookback      = $window.FindName("txtLookback")
$btnAnalyze       = $window.FindName("btnAnalyze")
$dgTimeline       = $window.FindName("dgTimeline")
$txtConclusion    = $window.FindName("txtConclusion")
$txtLogDetail     = $window.FindName("txtLogDetail")

$btnScanCerts     = $window.FindName("btnScanCerts")
$dgCerts          = $window.FindName("dgCerts")
$btnRemoveExpired = $window.FindName("btnRemoveExpired")
$btnLaunchMsScript= $window.FindName("btnLaunchMsScript")

# Registry Controls
$pnlRegistryKeys  = $window.FindName("pnlRegistryKeys")
$btnRefreshReg    = $window.FindName("btnRefreshReg")
$btnApplyReg      = $window.FindName("btnApplyReg")

$chkAck           = $window.FindName("chkAck")
$btnBackupConfig  = $window.FindName("btnBackupConfig")
$btnResetReg      = $window.FindName("btnResetReg")

$Global:StatusBlock = $window.FindName("txtStatus")
$Global:RegUiControls = @() # To store references for state reading

# -- Helper for UI Generation --
function Load-RegistryUI {
    $pnlRegistryKeys.Children.Clear()
    $Global:RegUiControls = @()
    
    $currentRegs = Get-RegSettings
    
    foreach ($kDef in $Global:KnownRegKeys) {
        $keyName = $kDef.Name
        $keyDesc = $kDef.Desc
        
        # Determine Current State
        $currValObj = $currentRegs | Where-Object { $_.Key -eq $keyName }
        $exists = ($currValObj -ne $null)
        $val = if ($exists) { $currValObj.Value } else { $kDef.Options[1] } # Default to FALSE if missing

        # -- Build Row UI --
        
        # Outer Border
        $border = New-Object System.Windows.Controls.Border
        $border.BorderThickness = "0,0,0,1"
        $border.BorderBrush = "#CCCCCC"
        $border.Padding = "5"
        $border.Margin = "0,0,0,5"
        
        # Grid layout for row
        $grid = New-Object System.Windows.Controls.Grid
        $grid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1, "Star") })) # Name
        $grid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(150, "Pixel") })) # Value

        # StackPanel for Left Side (Checkbox + Desc)
        $spLeft = New-Object System.Windows.Controls.StackPanel
        
        $chk = New-Object System.Windows.Controls.CheckBox
        $chk.Content = $keyName
        $chk.FontWeight = "Bold"
        $chk.IsChecked = $exists
        $spLeft.Children.Add($chk)
        
        $desc = New-Object System.Windows.Controls.TextBlock
        $desc.Text = $keyDesc
        $desc.FontSize = 10
        $desc.Foreground = "#666666"
        $desc.TextWrapping = "Wrap"
        $desc.Margin = "20,2,0,0"
        $spLeft.Children.Add($desc)
        
        [System.Windows.Controls.Grid]::SetColumn($spLeft, 0)
        $grid.Children.Add($spLeft)

        # Combo for Right Side
        $combo = New-Object System.Windows.Controls.ComboBox
        $combo.Margin = "10,0,0,0"
        foreach ($opt in $kDef.Options) { [void]$combo.Items.Add($opt) }
        $combo.Text = $val
        $combo.IsEnabled = $exists
        
        # Handle Enable/Disable
        # FIX: Store combo in Tag to avoid PS 5.1 variable scope issues
        $chk.Tag = $combo
        $chk.Add_Checked({ ($this.Tag).IsEnabled = $true })
        $chk.Add_Unchecked({ ($this.Tag).IsEnabled = $false })
        
        [System.Windows.Controls.Grid]::SetColumn($combo, 1)
        $grid.Children.Add($combo)
        
        $border.Child = $grid
        [void]$pnlRegistryKeys.Children.Add($border)

        # Store Ref for Apply
        $Global:RegUiControls += [PSCustomObject]@{
            Name = $keyName
            CheckControl = $chk
            ComboControl = $combo
        }
    }
}

# -- Event Handlers --

# 1. Overview
$btnRefreshPrereq.Add_Click({
    Write-Status "Checking prerequisites..."
    $data = Test-NpsMfaPrerequisites
    
    # Convert to standard DataTable for WPF Grid
    $table = New-Object System.Data.DataTable
    $table.Columns.Add("Check")
    $table.Columns.Add("Status")
    $table.Columns.Add("Details")
    
    foreach ($d in $data) { $table.Rows.Add($d.Check, $d.Status, $d.Details) }
    $dgPrereqs.ItemsSource = $table.DefaultView
    Write-Status "Prerequisites check complete."
})

# 2. Analysis
$btnAnalyze.Add_Click({
    $user = $txtLogUser.Text
    $min = $txtLookback.Text -as [int]
    if (-not $min) { $min = 30 }

    if ([string]::IsNullOrWhiteSpace($user)) {
        [System.Windows.MessageBox]::Show("Please enter a User Name to filter.")
        return
    }

    Write-Status "Analyzing flow for $user (Last $min mins)..."
    $window.Cursor = [System.Windows.Input.Cursors]::Wait

    try {
        $result = Trace-AuthFlow -UserName $user -LookbackMinutes $min
        
        $table = New-Object System.Data.DataTable
        $table.Columns.Add("Timestamp")
        $table.Columns.Add("Source")
        $table.Columns.Add("Details")
        $table.Columns.Add("RawMessage") # Hidden detail

        foreach ($row in $result.Timeline) {
            $table.Rows.Add($row.Timestamp, $row.Source, $row.Details, $row.RawMessage)
        }

        $dgTimeline.ItemsSource = $table.DefaultView
        $txtConclusion.Text = $result.Conclusion
    }
    catch {
        Write-Status "Error during analysis: $_"
    }
    finally {
        $window.Cursor = [System.Windows.Input.Cursors]::Arrow
        Write-Status "Analysis complete."
    }
})

$dgTimeline.Add_SelectionChanged({
    if ($dgTimeline.SelectedItem) {
        $row = $dgTimeline.SelectedItem
        # DataRowView wrapper
        $txtLogDetail.Text = $row["RawMessage"]
    }
})

# 3. Certificates
$UpdateCertGrid = {
    $certs = Get-MfaCerts
    $table = New-Object System.Data.DataTable
    $table.Columns.Add("Status")
    $table.Columns.Add("DaysLeft", [int])
    $table.Columns.Add("NotAfter")
    $table.Columns.Add("Thumbprint")
    $table.Columns.Add("Subject")
    
    foreach ($c in $certs) {
        $table.Rows.Add($c.Status, $c.DaysLeft, $c.NotAfter, $c.Thumbprint, $c.Subject)
    }
    $dgCerts.ItemsSource = $table.DefaultView
}

$btnScanCerts.Add_Click({
    Write-Status "Scanning certificates..."
    &$UpdateCertGrid
    Write-Status "Scan complete."
})

$btnRemoveExpired.Add_Click({
    $selected = $dgCerts.SelectedItem
    if (-not $selected) {
        [System.Windows.MessageBox]::Show("Select a certificate row first.")
        return
    }
    
    # Check if actually expired to be safe
    if ($selected["Status"] -ne "Expired") {
        $confirm = [System.Windows.MessageBox]::Show("This certificate is NOT marked as expired. Are you sure you want to delete it?", "Confirm Delete", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
        if ($confirm -ne 'Yes') { return }
    }

    $tp = $selected["Thumbprint"]
    Write-Status "Removing $tp..."
    Remove-OldMfaCerts -ThumbprintsToRemove @($tp)
    &$UpdateCertGrid
})

$btnLaunchMsScript.Add_Click({
    if (Test-Path $Global:MfaDefScript) {
        Start-Process powershell -ArgumentList "-NoExit -File `"$Global:MfaDefScript`""
    } else {
        [System.Windows.MessageBox]::Show("Standard Microsoft script not found at $Global:MfaDefScript")
    }
})

# 4. Registry - Handlers
$btnRefreshReg.Add_Click({
    Write-Status "Reloading Registry UI..."
    Load-RegistryUI
    Write-Status "Registry UI Refreshed."
})

$btnApplyReg.Add_Click({
    $confirm = [System.Windows.MessageBox]::Show("This will update the registry keys for Azure MFA. Continue?", "Apply Config", [System.Windows.MessageBoxButton]::YesNo)
    if ($confirm -ne 'Yes') { return }
    
    Write-Status "Applying Registry Changes..."
    
    foreach ($ctrl in $Global:RegUiControls) {
        $name = $ctrl.Name
        $isChecked = $ctrl.CheckControl.IsChecked
        $val = $ctrl.ComboControl.Text
        
        if ($isChecked) {
            # Create/Update
            try {
                Set-RegSetting -Name $name -Value $val
                Write-Status "Updated $($name) -> $val"
            } catch {
                Write-Status "Error updating $($name): $_"
            }
        } else {
            # Delete if exists
            try {
                Remove-ItemProperty -Path $Global:MfaRegPath -Name $name -ErrorAction SilentlyContinue
                Write-Status "Removed $($name) (if existed)"
            } catch {
                Write-Status "Error removing $($name): $_"
            }
        }
    }
    
    [System.Windows.MessageBox]::Show("Configuration Applied. You may need to restart the NPS Service for changes to take effect.")
    Load-RegistryUI # Refresh UI to show state
})

# Initial Load for Registry
$pnlRegistryKeys.Add_Loaded({ Load-RegistryUI })


# 5. Advanced / Start Fresh
$chkAck.Add_Checked({
    $btnBackupConfig.IsEnabled = $true
    $btnResetReg.IsEnabled = $true
})

$chkAck.Add_Unchecked({
    $btnBackupConfig.IsEnabled = $false
    $btnResetReg.IsEnabled = $false
})

$btnBackupConfig.Add_Click({
    $ts = (Get-Date).ToString("yyyyMMdd_HHmm")
    $backupDir = "$OutputPath\Backup_$ts"
    New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
    
    # NPS Config
    Invoke-Expression "netsh nps show config > `"$backupDir\nps_config.xml`""
    
    # Reg Config
    Invoke-Expression "reg export HKLM\SOFTWARE\Microsoft\AzureMfa `"$backupDir\mfa_reg.reg`" /y"
    
    [System.Windows.MessageBox]::Show("Backup saved to $backupDir")
})

$btnResetReg.Add_Click({
    $res = [System.Windows.MessageBox]::Show("Reset Registry keys to default? This assumes a standard setup.", "Confirm", [System.Windows.MessageBoxButton]::YesNo)
    if ($res -eq 'Yes') {
        Set-RegSetting -Name "OVERRIDE_NUMBER_MATCHING_WITH_OTP" -Value "FALSE"
        Set-RegSetting -Name "REQUIRE_USER_MATCH" -Value "FALSE"
        # Refresh UI
        Load-RegistryUI
        [System.Windows.MessageBox]::Show("Registry keys reset.")
    }
})

# Initial Load
Write-Status "Application Loaded. Please check Overview."
$window.ShowDialog() | Out-Null