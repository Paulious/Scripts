[CmdletBinding(SupportsShouldProcess = $true)]

param(
    [Parameter(Mandatory = $false)]
    [string]$KeePassDbPath,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$KeePassExePath = 'C:\Program Files\KeePass Password Safe 2\KeePass.exe'
)

$paths = @(
    "C:\Program Files\KeePass Password Safe 2\KeePass.exe",
    "C:\Program Files (x86)\KeePass Password Safe 2x\KeePass.exe"
)

# Function to check if a path exists
function Test-KeePassPath {
    param (
        [string]$Path
    )
    if (Test-Path $Path) {
        return $true
    } else {
        return $false
    }
}

# Check if the provided KeePassExePath exists
if (-not (Test-KeePassPath -Path $KeePassExePath)) {
    foreach ($path in $paths) {
        if (Test-KeePassPath -Path $path) {
            $KeePassExePath = $path
            Write-Output "KeePass found at $KeePassExePath"
            break
        }
    }
}

if (-not (Test-KeePassPath -Path $KeePassExePath)) {
    Write-Output "KeePass not found in the specified paths."
} else {
    Write-Output "Using KeePass executable at $KeePassExePath"
}


[CmdletBinding(SupportsShouldProcess = $true)]

param(
    [Parameter(Mandatory = $false)]
    [string]$KeePassDbPath,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$KeePassExePath = 'C:\Program Files\KeePass Password Safe 2\KeePass.exe'
)

$paths = @(
    "C:\Program Files\KeePass Password Safe 2\KeePass.exe",
    "C:\Program Files (x86)\KeePass Password Safe 2x\KeePass.exe"
)

# Function to check if a path exists
function Test-KeePassPath {
    param (
        [string]$Path
    )
    if (Test-Path $Path) {
        return $true
    } else {
        return $false
    }
}

# Check if the provided KeePassExePath exists
if (-not (Test-KeePassPath -Path $KeePassExePath)) {
    foreach ($path in $paths) {
        if (Test-KeePassPath -Path $path) {
            $KeePassExePath = $path
            Write-Output "KeePass found at $KeePassExePath"
            break
        }
    }
}

if (-not (Test-KeePassPath -Path $KeePassExePath)) {
    Write-Output "KeePass not found in the specified paths."
} else {
    Write-Output "Using KeePass executable at $KeePassExePath"
}


# --- Prerequisite Checks ---
$ErrorActionPreference = 'Stop' # Use Stop for prerequisite checks too

# Check for bw.exe alongside the script
[CmdletBinding(SupportsShouldProcess = $true)]

param(
    [Parameter(Mandatory = $false)]
    [string]$KeePassDbPath,

    [Parameter(Mandatory = $false)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$KeePassExePath = 'C:\Program Files\KeePass Password Safe 2\KeePass.exe'
)

$paths = @(
    "C:\Program Files\KeePass Password Safe 2\KeePass.exe",
    "C:\Program Files (x86)\KeePass Password Safe 2x\KeePass.exe"
)

# Function to check if a path exists
function Test-KeePassPath {
    param (
        [string]$Path
    )
    if (Test-Path $Path) {
        return $true
    } else {
        return $false
    }
}

# Check if the provided KeePassExePath exists
if (-not (Test-KeePassPath -Path $KeePassExePath)) {
    foreach ($path in $paths) {
        if (Test-KeePassPath -Path $path) {
            $KeePassExePath = $path
            Write-Output "KeePass found at $KeePassExePath"
            break
        }
    }
}

if (-not (Test-KeePassPath -Path $KeePassExePath)) {
    Write-Output "KeePass not found in the specified paths."
    exit 1
} else {
    Write-Output "Using KeePass executable at $KeePassExePath"
}

# --- Prerequisite Checks ---
$ErrorActionPreference = 'Stop' # Use Stop for prerequisite checks too

# Check for bw.exe alongside the script
# $PSScriptRoot is the directory containing the script file
$scriptDir = $PSScriptRoot
$bwExePath = Join-Path -Path $scriptDir -ChildPath "bw.exe"
if (-not (Test-Path -Path $bwExePath -PathType Leaf)) {
    throw "Bitwarden CLI executable 'bw.exe' not found in the script directory: $scriptDir. Please place bw.exe alongside the script."
}
Write-Verbose "Using Bitwarden CLI executable: $bwExePath"

# --- Script Main Logic ---
# Variables for cleanup scope
$plainTextPass = $null
$pd = $null
$xmlPath = $null
$keepassInitialized = $false

try {
    # --- Initialize KeePass Environment ---
    Write-Verbose "Using KeePass executable path: $KeePassExePath"
    if (-not (Test-Path -Path $KeePassExePath -PathType Leaf)) {
        throw "KeePass.exe not found at the specified path: $KeePassExePath. Please verify the path or provide the correct one using -KeePassExePath."
    }

    try {
        Write-Verbose "Attempting to load KeePass assembly: $KeePassExePath"
        [System.Reflection.Assembly]::LoadFrom($KeePassExePath) | Out-Null
        Write-Verbose "KeePass assembly loaded. Initializing KeePass environment..."
        [KeePass.Program]::CommonInitialize()
        $keepassInitialized = $true
        Write-Verbose "KeePass environment initialized successfully."
    }
    catch {
        Write-Error "Failed during KeePass assembly load or initialization from '$KeePassExePath'. Ensure KeePassLib.dll exists (see workaround). Error: $($_.Exception.ToString())"
        exit 1 # Use exit here as it's a fundamental failure before main ops
    }

    # Prompt user for KeePass database path if not provided
    if ([string]::IsNullOrWhiteSpace($KeePassDbPath)) {
        $KeePassDbPath = Read-Host "Please enter the path to your KeePass database file"
    }

    if ([string]::IsNullOrWhiteSpace($KeePassDbPath)) {
        throw "KeePass database path not provided."
    }

    if (-not (Test-Path -Path $KeePassDbPath -PathType Leaf)) {
        throw "KeePass database file not found at: $KeePassDbPath"
    }

    Write-Verbose "Using KeePass database: $KeePassDbPath"
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}

# --- Additional Script Logic ---
# Place your additional script logic here

# Example of additional logic:
try {
    # Your additional script logic here
    Write-Verbose "Starting additional script logic..."
    # Example: Load KeePass database
    $pd = [KeePassLib.PwDatabase]::new()
    $ioConnInfo = [KeePassLib.Serialization.IOConnectionInfo]::new()
    $ioConnInfo.Path = $KeePassDbPath
    $pd.Open($ioConnInfo, $true)
    Write-Verbose "KeePass database loaded successfully."
}
catch {
    Write-Error "An error occurred during additional script logic: $_"
    exit 1
}

# Check for bw.exe alongside the script
# $PSScriptRoot is the directory containing the script file
$scriptDir = $PSScriptRoot
$bwExePath = Join-Path -Path $scriptDir -ChildPath "bw.exe"
if (-not (Test-Path -Path $bwExePath -PathType Leaf)) {
    throw "Bitwarden CLI executable 'bw.exe' not found in the script directory: $scriptDir. Please place bw.exe alongside the script."
}
Write-Verbose "Using Bitwarden CLI executable: $bwExePath"


# --- Script Main Logic ---
# Variables for cleanup scope
$plainTextPass = $null
$pd = $null
$xmlPath = $null
$keepassInitialized = $false

try {
    # --- Initialize KeePass Environment ---
    Write-Verbose "Using KeePass executable path: $KeePassExePath"
    if (-not (Test-Path -Path $KeePassExePath -PathType Leaf)) {
        throw "KeePass.exe not found at the specified path: $KeePassExePath. Please verify the path or provide the correct one using -KeePassExePath."
    }

    try {
        Write-Verbose "Attempting to load KeePass assembly: $KeePassExePath"
        [System.Reflection.Assembly]::LoadFrom($KeePassExePath) | Out-Null
        Write-Verbose "KeePass assembly loaded. Initializing KeePass environment..."
        [KeePass.Program]::CommonInitialize()
        $keepassInitialized = $true
        Write-Verbose "KeePass environment initialized successfully."
    }
    catch {
        Write-Error "Failed during KeePass assembly load or initialization from '$KeePassExePath'. Ensure KeePassLib.dll exists (see workaround). Error: $($_.Exception.ToString())"
        exit 1 # Use exit here as it's a fundamental failure before main ops
    }


    # Determine KeePass database path
    if ([string]::IsNullOrWhiteSpace($KeePassDbPath)) {
       # $oneDrivePath = [Environment]::GetEnvironmentVariable('OneDrive')

function getloggedindetails() {
        <#
    .SYNOPSIS
    This function is used to find the logged in user SID and username when running as System
    .DESCRIPTION
    This function is used to find the logged in user SID and username when running as System
    .EXAMPLE
    getloggedindetails
    Returns the SID and Username in an array
    .NOTES
    NAME: getloggedindetails
    Written by: Andrew Taylor (https://andrewstaylor.com)
    #>
    ##Find logged in username
    $user = Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" |
      ForEach-Object { $_.GetOwner() } |
      Select-Object -Unique -Expand User
    
    ##Find logged in user's SID
    ##Loop through registry profilelist until ProfileImagePath matches and return the path
        $path= "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*"
        $sid = (Get-ItemProperty -Path $path | Where-Object { $_.ProfileImagePath -like "*$user" }).PSChildName

    $return = $sid, $user
    
    return $return
    }

$loggedinuser = getloggedindetails
$sid = $loggedinuser[0]

$onedrivepath = (Get-ItemProperty -Path Registry::HKEY_USERS\$sid\Environment -Name Onedrive).Onedrive

  
        if ([string]::IsNullOrWhiteSpace($oneDrivePath)) {
            throw "OneDrive environment variable not found and KeePassDbPath not provided."
        }
        $resolvedKeePassDbPath = Join-Path -Path $oneDrivePath -ChildPath "Documents\Database.kdbx"
    }
    else {
        $resolvedKeePassDbPath = $KeePassDbPath
    }

    if (-not (Test-Path -Path $resolvedKeePassDbPath -PathType Leaf)) {
        throw "KeePass database file not found at: $resolvedKeePassDbPath"
    }

    Write-Verbose "Using KeePass database: $resolvedKeePassDbPath"

    # --- KeePass Operations ---
    $ioc = [KeePassLib.Serialization.IOConnectionInfo]::FromPath($resolvedKeePassDbPath)

    $securePass = Read-Host "Enter your KeePass Master Password for '$($resolvedKeePassDbPath)'" -AsSecureString
    if ($securePass.Length -eq 0) { throw "Password cannot be empty." }

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass)
    $plainTextPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    $securePass.Dispose()

    $ck = New-Object KeePassLib.Keys.CompositeKey
    $kp = New-Object KeePassLib.Keys.KcpPassword($plainTextPass)
    $ck.AddUserKey($kp)

    Clear-Variable plainTextPass -ErrorAction SilentlyContinue
    $plainTextPass = $null
    Write-Verbose "Plaintext password variable cleared from script scope."

    Write-Verbose "Opening KeePass database..."
    $pd = New-Object KeePassLib.PwDatabase
    $pd.Open($ioc, $ck, $null)
    Write-Host "KeePass database opened successfully."

    # Prepare for XML Export
    $xmlPath = Join-Path -Path $env:TEMP -ChildPath "keepass_export_$(New-Guid).xml"
    Write-Verbose "Exporting database to temporary file: $xmlPath"

    $pei = New-Object KeePass.DataExchange.PwExportInfo($pd.RootGroup, $pd)
    $iocOut = [KeePassLib.Serialization.IOConnectionInfo]::FromPath($xmlPath)
    $ffp = [KeePass.Program]::FileFormatPool.Find('KeePass XML (2.x)')

    if ($null -eq $ffp) {
        throw "Could not find the 'KeePass XML (2.x)' export format. Ensure KeePass is correctly initialized."
    }

    if ($ffp.SupportsExport) {
        $outputStream = $null
        try {
            $outputStream = [KeePassLib.Serialization.IOConnection]::OpenWrite($iocOut)
            $ffp.Export($pei, $outputStream, $null)
            Write-Host "Successfully exported KeePass database to $xmlPath"
        }
        catch {
            # If export fails, no point continuing to Bitwarden ops
            throw "Failed during KeePass XML export: $($_.Exception.Message)"
        }
        finally {
            if ($null -ne $outputStream) { $outputStream.Dispose(); Write-Verbose "KeePass export output stream disposed." }
        }
    }
    else {
        throw "'KeePass XML (2.x)' format does not support export."
    }

    # --- Bitwarden Operations ---
    Write-Host "Starting Bitwarden CLI operations using '$bwExePath'..."

    # Login (must succeed to continue)
    Write-Host "Attempting Bitwarden login (may require interaction)..."
    try {
        # Use '&' call operator with the full path to bw.exe
        & $bwExePath login
        Write-Host "Bitwarden login command executed successfully."
    } catch {
        # Throw an error to stop further BW operations in this try block
        # This error WILL be caught by the outer catch block
        throw "Bitwarden login failed. Halting further Bitwarden operations. Error: $($_.Exception.Message)"
    }

    # Import KeePass XML (Only runs if login succeeded)
    Write-Host "Importing KeePass XML into Bitwarden..."
    $importFormat = "keepass2xml"
    try {
        if ($PSCmdlet.ShouldProcess("Bitwarden Vault", "Import from $xmlPath")) {
            & $bwExePath import $importFormat $xmlPath
            Write-Host "Bitwarden import command executed successfully."
        }
    } catch {
        # If import fails, we might still want to lock/logout, so just write error and continue? Or throw?
        # Let's throw to be safe - if import fails, user should investigate before lock/logout potentially hides state.
        Write-Error "Failed to execute 'bw import'. Error: $($_.Exception.Message)"
        throw "Bitwarden import failed."
    }

    # Lock Bitwarden Vault (Only runs if login and import succeeded)
    Write-Host "Locking Bitwarden vault..."
    try {
         if ($PSCmdlet.ShouldProcess("Bitwarden Vault", "Lock")) {
            & $bwExePath lock
            Write-Host "Bitwarden lock command executed."
         }
    } catch {
        # Failure to lock is probably not critical enough to stop logout, just warn
        Write-Warning "Failed to execute 'bw lock'. Error: $($_.Exception.Message)"
    }

    # Logout from Bitwarden (Only runs if login and import succeeded)
    Write-Host "Logging out from Bitwarden..."
    try {
        if ($PSCmdlet.ShouldProcess("Bitwarden CLI", "Logout")) {
           & $bwExePath logout
           Write-Host "Bitwarden logout command executed."
        }
    } catch {
        # Failure to logout, just warn
        Write-Warning "Failed to execute 'bw logout'. Error: $($_.Exception.Message)"
    }

}
catch {
    # Catches errors from KeePass init/ops OR re-thrown bw login/import errors
    Write-Error "An error occurred during the script execution: $($_.Exception.Message)"
}
finally {
    # --- Cleanup ---
    Write-Verbose "Executing cleanup actions..."

    # Ensure plaintext password variable is cleared
    if ($null -ne $plainTextPass) { Clear-Variable plainTextPass -ErrorAction SilentlyContinue; Write-Verbose "Plaintext password cleared in finally."}

    # Close KeePass database if it was opened
    if ($null -ne $pd -and $pd.IsOpen) {
        try { $pd.Close(); Write-Host "KeePass database closed." }
        catch { Write-Warning "Failed to close KeePass database: $($_.Exception.Message)" }
    }

    # Terminate KeePass environment if it was initialized
    if ($keepassInitialized) {
        Write-Verbose "Terminating KeePass environment..."
        try {
            [KeePass.Program]::CommonTerminate()
            Write-Verbose "KeePass environment terminated."
        }
        catch {
            Write-Warning "Failed to terminate KeePass environment cleanly: $($_.Exception.Message)"
        }
    }

    # Delete of the temporary XML file if it exists
    if (-not [string]::IsNullOrWhiteSpace($xmlPath) -and (Test-Path $xmlPath) ) {
        Write-Verbose "Performing standard delete (fast, insecure) on: $xmlPath"
        try {
             if ($PSCmdlet.ShouldProcess($xmlPath, "Remove File (Standard Delete)")) {
                 Remove-Item -Path $xmlPath -Force -ErrorAction Stop
                 Write-Host "Temporary XML file deleted (standard delete): $xmlPath"
             }
        } catch {
            Write-Error "Failed to delete temporary file '$xmlPath'. Manual deletion might be required. Error: $($_.Exception.Message)"
        }
    } else {
        Write-Verbose "XML Path variable was empty or file '$xmlPath' does not exist, skipping delete."
    }

    Write-Host "Script finished."
}
