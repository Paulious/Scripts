$ComputerName = $env:COMPUTERNAME                               # Define computer name once for the whole script
$MSIFile = "TeamViewer_Host.msi"                                # MSI file name
$MSIPath = Join-Path -Path $PSScriptRoot -ChildPath $MSIFile    # Full path to the MSI file
$LogFile = "c:\windows\logs\$($MSIFile)_Install.log"            # Log file path

# How long to wait for the Host to be ready, and how many times to try the assignment
$ReadyTimeoutSeconds = 300
$AssignRetries       = 3
$AssignRetryDelay    = 30

# Switch based on the first two characters
switch ($ComputerName.Substring(0, 2)) {
    "AT" { $customconfigid = '6nvggcf'; $assignmentid="0001CoABChCy95fwkvwR8IaMxY9cF1hREigIACAAAgAJAHB61nqGykCoJ9Ir3J69XW9GEwyXU0YaTG6S9p8z0XtcGkCINNk_sGpzvhRVrdRV85wARDvu_lAEAv4PLjGOPQ-BzPb0_PeQzWtzOPDJvmSf6ouzBAnzmZerWsrwc0XkzMM9IAEQi8W_uwM=" ; break }
    "CH" { $customconfigid = '6smem5b'; $assignmentid="0001CoABChCoUwaAkv0R8KXx3mUH1eegEigIACAAAgAJAHLbcn3v9orbRPqWRyq1KinE7Tf1jK2ka6lCktTlf3QIGkCVGnumi5YA258ONxqL3d6XxRe5ZJXLFqhfgZabY5bsQD3blcCiqKuh9aoHJWjp2SoQyOwfvfk_ZjVQlFRMw0r7IAEQreOnigo=" ; break }
    "BG" { $customconfigid = '6zncvrt'; $assignmentid="0001CoABChDDXN6wkv0R8J39iRNLYW_8EigIACAAAgAJAJZFKVjzz6MxX1M9xetOPcSmkK4EPY7hqbyc5VupSvkNGkDRomAZlNiLbmZF_ik_Asu4uklDzpMvS4EILYxPJgqAbuLNpDPmT3YwOUX6xFSVyztJVjeXzOfkjINWdbFS23FzIAEQzLrXuQ0=" ; break }
    "CZ" { $customconfigid = '64dfkne'; $assignmentid="0001CoABChDezzywkv0R8K8Jit5c_z6dEigIACAAAgAJANwoHW02ezDyIw6B9INER2gfx0NOpBh3eB1L9ls426S5GkAFyJvWgv0gScleC6X6FxycXqmS9rRCowM60L7t-P8B0NkjuZLRzmI1ZufEMwUGFYC6cja5PLI9le1y3c5KJfZsIAEQzMmajgo=" ; break }
    "HU" { $customconfigid = '67mm2r9'; $assignmentid="0001CoABChAe_lvgkv4R8JaDcMX7bMl2EigIACAAAgAJAFh82sRzvN1PAVkbd2x_F0Dx3HINBoAU5BazVR4h-SA3GkCmfen1x96hQZEYH1Zo_qbIxH5b4t1tUlMUn8jOOVtFMfB0cTJuEQkQVmhai3BOfoFmHnWNhs9fshlfRlNUI5lKIAEQyq2DvAs=" ; break }
    "HR" { $customconfigid = '6hmpaw5'; $assignmentid="0001CoABChA7ZmSAkv4R8Km_HKzVSgn1EigIACAAAgAJAGdB32p__kD0AT_85b3qr-r9Rp7QtDRE3ydo7joLqtKHGkAtThNqBR0M1LViRH4SWjuGITKoIkAsvhDYiY45M8p0uiYKvfUmlL0QtTCVS0sJj9k7ADjauABY9C8tVcwyGWqBIAEQk8Komw4=" ; break }
    "RO" { $customconfigid = '6ux6k8y'; $assignmentid="0001CoABChBT_Wfwkv4R8JkcMyR4ZxqqEigIACAAAgAJAKuWmtIsNQC_72nzoFHX6zlyRM-eoBT0meqsVuCWMF7zGkAqMSWFkVRAtnpScjU_68djR8GSpLbgFsh-w7qR484Cc4kg7hrSWoha7zo8dkhddzrqw0zpU55SMp9HinLR3P52IAEQqNCmlQI=" ; break }
    "SK" { $customconfigid = '6mgreku'; $assignmentid="0001CoABChBpkYugkv4R8IpvBsyPWnCHEigIACAAAgAJAJ9S5p8_3oNa6BriZGIIRIpcheIQ08hbirMp5zoeHhpCGkDWkqmK_H2J4gr7GZ49fCY84nRSiPJ_MIwyYA2cnNeIduIWAAH0quvsCShxx7x-QEzfHqeigyXBbAy9r4WKXq3gIAEQ0fjN9AM=" ; break }
    "DE" { $customconfigid = '6qmgufq'; $assignmentid="0001CoABChCP86fQbUAR8LeW2j1MpQIGEigIACAAAgAJAClBa-bmO6wKHMamrHwwsDsIoHTD7BDRaRUB0O0ajjlUGkA9XWQkNpczBbepRPtTGpTdoAXSPv33W_G5ycPm3QhQnbThGxn_5hiU_TP2vr5UFV43bXLnO4JNGhUa2ctezxFfIAEQ19akkgg=" ; break }
    "FR" { $customconfigid = '6czpt2q'; $assignmentid="0001CoABChCHwm1gkv4R8IGkorTlnQO9EigIACAAAgAJAFR7FPt0MsWv4kWWDaAxlPOZw4JZhaYsK9xb8C2QYsD3GkAqxYbTCi8eBt6xGt911YEON4omZw74LGzvAvAJyQsw0IZDJMKiZC6QpyRbYm8rXAWIy9SQwaQcgyWA8dXuGztmIAEQwq-J-w8=" ; break }
    "GB" { $customconfigid = '6sr2k9c'; $assignmentid="0001CoABChCb_Wmwkv4R8KAxslMbHFbVEigIACAAAgAJAKoEnxTQP0_l2dcPlfZnjhOaz51DNvjc_LWg1_w0EFw4GkAtf48ZkULDtjQQTaAMgR9uAcs48a2j2xsgXfE0UPzu5C1EBeD3IDibSEvdA8t_1GYIUB04Q7FhJ0lvgMW1P0gHIAEQtoSB4gg=" ; break }
    "IE" { $customconfigid = '62dgybs'; $assignmentid="0001CoABChDLxteAkv4R8IhPS-nbzdWEEigIACAAAgAJANiOMTksgXxtutkouSJUvFrbpNwc3lDm3Kd8qawJEA0kGkBgql7oc5JbgIQidiSdKNI-XUhthtRfvKqFBzit5G69HnWg0RhfyGwtiNcVFHmrIhdNt1QP-MX2NsydLS1E3BYCIAEQybOMvAs=" ; break }
    "NL" { $customconfigid = '6wa6ajs'; $assignmentid="0001CoABChDx1NDQkv4R8Ltkv5j4XbtHEigIACAAAgAJAJF5gybxoB9YswDcKC3z3t5HAZd9KGNe2I8WTz791p1LGkAID_zu1o4YW-u2tXzKLkO7SQzOM8n68gfIHZV5KU4vHUjSnq-LSdj20Iv9o2qMSPB7O9m1fbQa2DP-oKqZy8KGIAEQ5tHmlwM=" ; break }
    "DK" { $customconfigid = '693hu59'; $assignmentid="0001CoABChAOgrwQkv8R8KRlcDuT5UlkEigIACAAAgAJAPjlauFYfOgDj0AHYXOPo5CaWxr9aY48Erxo1RfCkPT2GkCWfU2pv8qZjvqLhdDK201Sw940c9GCT5QDpUxprCS5UuCSbsGaw5ej5tuOnxZShzOGvumm7xq-Aaf1N6kJYNJZIAEQs4-Gqwo=" ; break }
    "FI" { $customconfigid = '62c3n8q'; $assignmentid="0001CoABChAmgSkAkv8R8IgZBuk1ahhFEigIACAAAgAJAIrniG8w5anYiK0hXS9tW7hTq_qnQ7Cc6JHK-zs6NzdiGkBzOxnC6qeTw6l0wEUD6tjisMf6UZLDTrxwRqDTQP8sNSk5hwmH_mG0yfU_hOSpKVRwVsltDLwvb_5p3TepbouRIAEQgNbXgwE=" ; break }
    "NO" { $customconfigid = '6kfcdnm'; $assignmentid="0001CoABChA9tUEQkv8R8LxsNSW30qtFEigIACAAAgAJAF7TQOBHS9DeKEXxfy1MCB688WTkDNzXND_TPXgjAVTrGkBW5MTvczQUEugsRnU4hxYajDPiwXuNv1ygU95OHdxBMMxFrY9LzW85CuBUmfn3vKc9Hqs7ww0T0ImLQYcromCoIAEQ0bOjlAk=" ; break }
    "SE" { $customconfigid = '6hizu7c'; $assignmentid="0001CoABChBUOH-wkv8R8LHRYMTA19daEigIACAAAgAJABGvc5s9pOCjs8IsRFLiF2_4zxmzVQXILcm8lt9WvcDSGkAWbjOadGuBC21FwGPUa0Opd0QqWa-YtNXj4jjcPhl1ESxsue3yzRGMQgep9Xh4AG1b78K3tyNlUQiqjdugxhEmIAEQp9jZ2ww=" ; break }
    "LT" { $customconfigid = '6k647mj'; $assignmentid="0001CoABChBsworQkv8R8Ipq6WBm0kNFEigIACAAAgAJACKpKkBOb6AdkOuTL2e_jdVJHwMEvbZS2Xu0BoKgSOapGkBvr7Umk1jO2Wjr1ZuYZkFjFYARh0sTUV-weMy6cgWOpcZ9as5Wi_ESPgYjw75QdEb1o4MjI2Z9CyRW9pDXH_NlIAEQwpn9-gY=" ; break }
    "PL" { $customconfigid = '6rppngr'; $assignmentid="0001CoABChCGWPzgkv8R8L_lIHKNz1jBEigIACAAAgAJAHn7MUZwsr6WLerbB196JsGEtu2rd7qUjtTUMlXmrEgYGkArfMt7tVsv_kjvNB0MzvlJ069UwbF2i7KGXiuKRqgyZVBeA4aVYTpRjHDA1zU0iiVC6F7AGq0LvALYnnE2XRi8IAEQ44zR1gw=" ; break }
    "SI" { $customconfigid = '6psuvsv'; $assignmentid="0001CoABChA7Hi9gCBcR8YxSSdYwhiiHEigIACAAAgAJAA1N2lID15qHyB1OUbcRBPEOLu1lNgBAXjteyj-syloUGkBE_Xdto9WMBQrvcruR3FKjNbXUQrQcK1QPAw4uF7Rq0XZtXRxKLXP7PrV-pkOZhAiG6JMphNAT4moI38_-mVaXIAEQ75iNkQI=" ; break }
    "NI" { $customconfigid = '6bwwsh9'; $assignmentid="0001CoABChDx1NDQkv4R8Ltkv5j4XbtHEigIACAAAgAJAJF5gybxoB9YswDcKC3z3t5HAZd9KGNe2I8WTz791p1LGkAID_zu1o4YW-u2tXzKLkO7SQzOM8n68gfIHZV5KU4vHUjSnq-LSdj20Iv9o2qMSPB7O9m1fbQa2DP-oKqZy8KGIAEQ5tHmlwM=" ; break }
    default { Write-Host "Failed to find a custom config ID" ; exit 1}
}
# Switch to identify devices DEIG-DUES for HQ devices (only if the name is long enough to check)
if ($ComputerName.Length -ge 9) {
    switch ($ComputerName.Substring(5, 4)) {
        "DUES" { $customconfigid = '679r2ip'; $assignmentid="0001CoABChBedaUgBa8R8YRYed_4CxddEigIACAAAgAJAEbeosv_ztZsW7CCuSYdCyc-YTrtWZ-vrCH0WIsX7i04GkAUn30d64HQte9E8DtqoE_G4FvNkTEu7qwoZtECSHMWIqjcp4DrMbc05Y_6net6e9_FTq0YRfzl2kETElzKco0hIAEQ7fK5wQc=" ; break }
    }
}

###### Remove existing TeamViewer installations ######
$Installations = Get-Package -Name "*TeamViewer*" -ErrorAction SilentlyContinue

foreach ($Install in $Installations) {
    Write-Host "Uninstalling TeamViewer package: $($Install.Name) Version: $($Install.Version)"
    try {
        Uninstall-Package -InputObject $Install -Force -ErrorAction Stop
        Write-Host "Successfully uninstalled: $($Install.Name)"
    } catch {
        Write-Host "Failed to uninstall: $($Install.Name) - $($_.Exception.Message)"
    }
}

# Remove leftover folders
$paths = @("C:\Program Files\TeamViewer", "C:\Program Files (x86)\TeamViewer")
foreach ($path in $paths) {
    if (Test-Path $path) {
        try {
            Write-Host "Attempting to remove folder: $path"
            Remove-Item -Path $path -Recurse -Force
            Write-Host "Removed folder: $path"
        } catch {
            Write-Host "Failed to remove folder ${path}: $($_.Exception.Message)"
        }
    } else {
        Write-Host "Folder not found: $path"
    }
}

Start-Sleep 5

###### Install TeamViewer Host ######
# Prepare MSI arguments
$MSIArguments = @(
    "/i",                               # Argument 1: /i for install
    "`"$MSIPath`"",                     # Argument 2: /i and the quoted MSI path
    "CUSTOMCONFIGID=$customconfigid",   # Argument 3: Custom Config ID
    "/qn",                              # Argument 4: Quiet mode
    "/norestart",                       # Argument 5: Suppress restart
    "ADDLOCAL=ALL",                     # Argument 6: Install all features
    "REMOVE=f.DesktopShortcut",         # Argument 7: Remove desktop shortcut
    "/L*V",                             # Argument 8: Logging switch
    "`"$LogFile`""                      # Argument 9: The quoted log file path
)

Write-Host "Using Custom Config ID: $customconfigid"

# Start the installation process
$Process = Start-Process -FilePath "msiexec.exe" `
    -ArgumentList $MSIArguments `
    -Wait `
    -NoNewWindow `
    -PassThru

# Check the exit code - stop here if the install failed, no point trying to assign
if ($Process.ExitCode -eq 0) {
    Write-Host "Installation of $MSIFile completed successfully (Exit Code: 0)."
} elseif ($Process.ExitCode -eq 3010) {
    Write-Host "Installation of $MSIFile completed successfully, but a reboot is required (Exit Code: 3010)."
} else {
    Write-Host "Installation of $MSIFile failed with Exit Code: $($Process.ExitCode). Check the log file for details: $LogFile"
    exit $Process.ExitCode
}

###### Wait for TeamViewer Host to be ready ######
# Ready = exe present + service running + Host has registered (ClientID in registry)
function Get-TVClientId {
    foreach ($key in @("HKLM:\SOFTWARE\TeamViewer", "HKLM:\SOFTWARE\WOW6432Node\TeamViewer")) {
        $val = (Get-ItemProperty -Path $key -Name ClientID -ErrorAction SilentlyContinue).ClientID
        if ($val) { return $val }
    }
    return $null
}

function Test-TVReady {
    $exe = @("C:\Program Files\TeamViewer\TeamViewer.exe", "C:\Program Files (x86)\TeamViewer\TeamViewer.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    $svc = Get-Service -Name "TeamViewer" -ErrorAction SilentlyContinue
    $id  = Get-TVClientId
    [pscustomobject]@{
        Exe     = $exe
        Service = ($svc -and $svc.Status -eq 'Running')
        ClientId = $id
        Ready   = [bool]($exe -and $svc -and $svc.Status -eq 'Running' -and $id)
    }
}

Write-Host "Waiting up to $ReadyTimeoutSeconds seconds for TeamViewer Host to be ready..."
$Timer = [System.Diagnostics.Stopwatch]::StartNew()
$State = Test-TVReady
while (-not $State.Ready -and $Timer.Elapsed.TotalSeconds -lt $ReadyTimeoutSeconds) {
    Write-Host ("Not ready yet (exe: {0}, service running: {1}, client ID: {2}) - checking again in 10 seconds" -f [bool]$State.Exe, $State.Service, [bool]$State.ClientId)
    # Try to start the service if it is installed but stopped
    $svc = Get-Service -Name "TeamViewer" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running' -and $svc.Status -ne 'StartPending') {
        Start-Service -Name "TeamViewer" -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 10
    $State = Test-TVReady
}

if (-not $State.Ready) {
    Write-Host "TeamViewer Host was not ready after $ReadyTimeoutSeconds seconds. Skipping assignment."
    exit 1
}
Write-Host "TeamViewer Host is ready (Client ID: $($State.ClientId)) after $([int]$Timer.Elapsed.TotalSeconds) seconds."

# Short settle time so the Host has finished loading before we call it
Start-Sleep -Seconds 10

###### Assign TeamViewer Host to account (with retries) ######
$Assigned = $false
for ($i = 1; $i -le $AssignRetries -and -not $Assigned; $i++) {
    Write-Host "Assigning TeamViewer Host to account (attempt $i of $AssignRetries)..."
    $Assign = Start-Process -FilePath $State.Exe -ArgumentList "assignment --id $assignmentid" -NoNewWindow -Wait -PassThru
    if ($Assign.ExitCode -eq 0) {
        $Assigned = $true
        Write-Host "Assignment command completed (Exit Code: 0)."
    } else {
        Write-Host "Assignment attempt $i failed with Exit Code: $($Assign.ExitCode)."
        if ($i -lt $AssignRetries) { Start-Sleep -Seconds $AssignRetryDelay }
    }
}

if (-not $Assigned) {
    Write-Host "Assignment failed after $AssignRetries attempts. Detection key not set so Intune will retry."
    exit 1
}

# Set TeamViewer Tensor registry key for detection (only reached when install, readiness and assignment all worked)
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Intersnack Group") -ne $true) {  New-Item "HKLM:\SOFTWARE\Intersnack Group" -force -ea SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Intersnack Group\TeamViewer") -ne $true) {  New-Item "HKLM:\SOFTWARE\Intersnack Group\TeamViewer" -force -ea SilentlyContinue };
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Intersnack Group\TeamViewer' -Name 'TeamViewerTensor' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;

exit 0
