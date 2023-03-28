<# 
enroll-dc-certificate.ps1 Version: 20220103
C. Hannebauer - glueckkanja-gab AG
T. Kunzi - glueckkanja-gab AG
With Feedback from P. Blattner - Aveniq Comicro AG

Checks whether a usable Kerberos Authentication certificate exists on the client.
When no valid certificate exists or its remaining validity is less than the required threshold (default 2 months),
then a new certificate is requested from the configured SCEP service.
If file sanlist.txt exists the FQDN's in it will be included into the SubjectAlternativeName attribute. e.g. ldap.acme.net

	.PARAMETER SCEPURL
    URL of the SCEP service to request a new certificate from if required.
	
	.PARAMETER SCEPChallenge
    The password used to authenticate the SCEP request

	.PARAMETER ValidityThreshold
    A new certificate is requested if the remaining validity of the existing certificate falls below this threshold

	.PARAMETER ValidityThresholdDays
    Alternative to ValidityThreshold, where the remaining validity is specified as the number of days

	.EXAMPLE
    .\enroll-dc-certificate.ps1 -SCEPURL https://scepman.azurewebsites.com/dc -SCEPChallenge password123

#>
param
( 
[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$false,HelpMessage='URL of the SCEP service')][string]$SCEPURL,
[Parameter(Position=1,Mandatory=$true,ValueFromPipeline=$false,HelpMessage='password used to authenticate the SCEP request')][string]$SCEPChallenge,
[Parameter(Position=2,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='a new certificate is requested if the remaining validity of the existing certificate falls below this threshold')][timespan]$ValidityThreshold,
[Parameter(Position=3,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='alternative to ValidityThreshold, where the remaining validity is specified as the number of days')][Int]$ValidityThresholdDays,
[Parameter(Position=4,Mandatory=$false,ValueFromPipeline=$false,HelpMessage="automatically log to a file in the script's directory")][switch]$LogToFile
)

function RequestNewDCCertificate($SCEPURL, $SCEPChallenge) {
    if (Test-Path -Path './sanlist.txt') { # Add SANs if this file exists
        Log-Information "using sanlist.txt for additional SANs"
        $params = @('newdccertext', $SCEPURL, $SCEPChallenge, 'sanlist.txt')
    }
    ELSE {
        $params = @('newdccert', $SCEPURL, $SCEPChallenge)
    }
    $errorOutput = $( $output = & './ScepClient.exe' $params ) 2>&1 # Capture error output, see https://stackoverflow.com/a/66861283/4054714

    $exitCode = $LASTEXITCODE

    $output = [string]::Join("`n", $output) # Sometimes $output is an array of the lines. Sometimes it's the whole output. This makes it deterministic.
    Log-Debug $output

    if (0 -eq $exitCode -and $null -eq $errorOutput) {
        Log-Information "Requested a new certificate, Exit Code $exitCode"
    } else {
        Log-Error "Error requesting a new certificate, Exit Code $exitCode, Error Output $errorOutput"
    }

    return $exitCode
}

# Main

# DEBUG 2012R2 missing Write-Information cmdlet
if ($null -eq (Get-Command "Write-Information" -ErrorAction SilentlyContinue)) {
    function Write-Information($MessageData) {
        Write-Host $MessageData
    }
}

function Log-Debug($message) {
    Write-Debug $message
    if ($LogToFile) {
        "$(Get-Date) - [DEBUG] $message" | Out-File $LogFile -Encoding unicode -Force -Append
    }
}

function Log-Information($message) {
    Write-Information $message
    if ($LogToFile) {
        "$(Get-Date) - [INFO] $message" | Out-File $LogFile -Encoding unicode -Force -Append
    }
}

function Log-Error($message) {
    Write-Error $message
    if ($LogToFile) {
        "$(Get-Date) - [ERROR] $message" | Out-File $LogFile -Encoding unicode -Force -Append
    }
}

# Variables e.g. for Logfile
$ScriptFolder = Split-Path -parent $MyInvocation.MyCommand.Definition
$ScriptName = ($MyInvocation.MyCommand.Name).Replace(".ps1","")
$LogFile = "$ScriptFolder\$ScriptName.log"
Set-Location $ScriptFolder # change path to scriptfolder

Log-Information "$(Get-Date) - Enroll DC Certificate Version 20220103"

if (!(Test-Path -Path './ScepClient.exe')) {   # The current working directory should be where the PS script and ScepClient.exe reside
    Log-Error "Cannot find ScepClient.exe in current working directory! Set current working directory to the correct path!"    
    exit 3 # The system cannot find the path specified
}

# Select the right ValidityThreshold
if ($null -eq $ValidityThreshold) {
    if (0 -eq $ValidityThresholdDays) {
        $ValidityThresholdDays = 30  # Default is 30 days
    }
    $ValidityThreshold = New-TimeSpan -Days $ValidityThresholdDays
}

## Search for an appropriate certificate
$sOidKerberosAuthentication = "1.3.6.1.5.2.3.5"
$CandidateCerts = @(Get-ChildItem cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey -and ( ( ($_.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq $sOidKerberosAuthentication }) -ne $null) -OR ($_.Extensions| Where-Object {$_.EnhancedKeyUsages | Where-Object {$_.Value -eq $sOidKerberosAuthentication} } ) ) })
Log-Debug "There are $($CandidateCerts.Length) certificates for Kerberos Authentication"
$ValidCandidateCerts = @($CandidateCerts | Where-Object { $_.Verify() })
Log-Debug "Of these Kerberos Authentication certificates, $($ValidCandidateCerts.Length) are valid"

# If multiple suitable certificates are found, use the one that expires last
$cert = $ValidCandidateCerts | Sort-Object NotAfter -Descending | Select-Object -First 1

if ($null -eq $cert) {
    Log-Information "No valid Kerberos Authentication certificate found. Requesting a new certificate."
    exit RequestNewDCCertificate -SCEPURL $SCEPURL -SCEPChallenge $SCEPChallenge
}
else {
    $remainingValidity = $cert.NotAfter.Subtract([DateTime]::UtcNow)

    if ($ValidityThreshold -ge $remainingValidity) {
        Log-Information "Lifetime of the existing Kerberos Authentication certificate is below the threshold; Requesting a new certificate." 
        exit RequestNewDCCertificate -SCEPURL $SCEPURL -SCEPChallenge $SCEPChallenge
    }
    else {
        Log-Information "There is an existing, valid Kerberos Authentication certificate with sufficient remaining lifetime:`r`nThumbprint: $($cert.Thumbprint)`r`nSubject: $($cert.Subject)`r`nIssuer: $($cert.Issuer)`r`nExpiration: $($cert.NotAfter)" 
        exit 0
    }
}