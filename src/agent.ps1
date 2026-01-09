# =============================================================================
# PROJECT: Windows Adaptive Security Agent (WASA)
# AUTHOR: Subhransu111
# VERSION: 1.0 (Lab MVP)
# DESC: Detects brute-force attacks and automatically hardens Windows security.
# =============================================================================

# --- CONFIGURATION ---
Write-Host " [INIT] STARTING WINDOWS SECURITY AGENT..." -ForegroundColor Cyan
$Global:FailedLogons = @{}

# --- RESPONDER MODULE ---

function Block-AttackerIP ($ip) {
    if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq "-" -or $ip -eq "::1" -or $ip -eq "127.0.0.1") { 
        Write-Host " [INFO] Skipped Firewall block (Target is Localhost/Safe)" -ForegroundColor DarkGray
        return 
    }

    try {
        $ruleName = "AutoBlock_$ip"
        $exists = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

        if (-not $exists) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -RemoteAddress $ip -Action Block -ErrorAction Stop | Out-Null
            Write-Host " [DEFENSE] FIREWALL: Blocked IP $ip" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host " [ERROR] Firewall block failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Harden-AccountPolicy {
    try {
        Write-Host " [ATTEMPTING] Hardening Account Lockout Policy..." -ForegroundColor Gray
        # NATIVE COMMAND: Sets lockout threshold to 3 attempts
        net accounts /lockoutthreshold:3 
        Write-Host " [HEALING] POLICY: System hardened (Lockout set to 3)" -ForegroundColor Cyan
    }
    catch {
        Write-Host " [ERROR] Policy update failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- SENSOR SETUP ---

# Define the Query
$query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery("Security", [System.Diagnostics.Eventing.Reader.PathType]::LogName, "*")

# Create the Watcher
$watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($query)

Register-ObjectEvent -InputObject $watcher -EventName "EventRecordWritten" -Action {
    
    $record = $Event.SourceEventArgs.EventRecord
    
    if ($null -eq $record) { return }
    if ($record.Id -eq 4625) {
        
        # PARSE XML
        $xml = [xml]$record.ToXml()
        $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetUserName"} | Select-Object -ExpandProperty "#text"
        $ip   = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "IpAddress"} | Select-Object -ExpandProperty "#text"

    

        # Initialize Memory
        if (-not $Global:FailedLogons.ContainsKey($user)) {
             $Global:FailedLogons[$user] = [System.Collections.ArrayList]@()
        }

        #Add CURRENT failure
        [void]$Global:FailedLogons[$user].Add((Get-Date))

        # Prune Old Entries (Keep only last 60 seconds)
        $timeWindow = (Get-Date).AddSeconds(-60)
        $cleanList  = $Global:FailedLogons[$user] | Where-Object { $_ -gt $timeWindow }
        $Global:FailedLogons[$user] = [System.Collections.ArrayList]@($cleanList)

        $failureCount = $Global:FailedLogons[$user].Count

        if ($failureCount -ge 5) {
            Write-Host " [ALERT] BRUTE FORCE DETECTED: User $user ($failureCount failures)" -ForegroundColor Red -BackgroundColor Yellow
            
            if ($failureCount -eq 5) {
                Harden-AccountPolicy
                Block-AttackerIP -ip $ip
            }
        }
        
        # LOG OUTPUT
        $detectObject = [PSCustomObject]@{
            EventType    = "LogonFailed"
            TimeStamp    = $record.TimeCreated
            User         = $user
            SourceIp     = $ip
            EventId      = 4625
            FailureCount = $failureCount
        }
        Write-Host ($detectObject | ConvertTo-Json -Compress) -ForegroundColor Gray
    }
}

$watcher.Enabled = $true
Write-Host " [INFO] LISTENING FOR ATTACKS..." -ForegroundColor Green

while ($true) {
    Start-Sleep -Seconds 1
}