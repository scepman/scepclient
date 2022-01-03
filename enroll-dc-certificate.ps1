<# 
enroll-dc-certificate.ps1 Version: 20211228
C. Hannebauer - glueckkanja-gab AG
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

	.EXAMPLE
    .\enroll-dc-certificate.ps1 -SCEPURL https://scepman.azurewebsites.com/dc -SCEPChallenge password123

#>
param
( 
[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$false,HelpMessage='URL of the SCEP service')][string]$SCEPURL,
[Parameter(Position=1,Mandatory=$true,ValueFromPipeline=$false,HelpMessage='password used to authenticate the SCEP request')][string]$SCEPChallenge,
[Parameter(Position=2,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='a new certificate is requested if the remaining validity of the existing certificate falls below this threshold')][Int]$ValidityThreshold
)

function RequestNewDCCertificate($SCEPURL, $SCEPChallenge) {
    if (Test-Path -Path './sanlist.txt') { # Add SANs if this file exists
        Write-Information "using sanlist.txt for additional SANs"
        "using sanlist.txt for additional SANs"| Out-File $LogFile -Append -Encoding unicode
        $output = ./ScepClient.exe newdccertext $SCEPURL $SCEPChallenge sanlist.txt
    }
    ELSE {
        $output = ./ScepClient.exe newdccert $SCEPURL $SCEPChallenge
    }
    $output = [string]::Join("`n", $output) # Sometimes $output is an array of the lines. Sometimes it's the whole output. This makes it deterministic.
    Write-Debug $output
    return $LASTEXITCODE
}

# Main

# DEBUG 2012R2 missing Write-Information cmdlet
if ((Get-Command "Write-Information" -ErrorAction SilentlyContinue) -eq $null) {
    function Write-Information($MessageData) {
        Write-Host $MessageData
    }
}

# Variables e.g. for Logfile
$ScriptFolder = Split-Path -parent $MyInvocation.MyCommand.Definition
$ScriptFullName = $MyInvocation.MyCommand.Name
$ScriptName = ($MyInvocation.MyCommand.Name).Replace(".ps1","")
$LogFile = "$ScriptFolder\$ScriptName.log"
Set-Location $ScriptFolder # change path to scriptfolder

Write-Information "$(Get-Date) - Enroll DC Certificate Version 20211227"
"$(Get-Date) - Enroll DC Certificate Version 20211227"| Out-File $LogFile -Encoding unicode -Force

if (!(Test-Path -Path './ScepClient.exe')) {   # The current working directory should be where the PS script and ScepClient.exe reside
    Write-Error "Cannot find ScepClient.exe in current working directory! Set current working directory to the correct path!"    
    "Cannot find ScepClient.exe in current working directory! Set current working directory to the correct path!"| Out-File $LogFile -Append -Encoding unicode
    exit 3 # The system cannot find the path specified
}

## Search for an appropriate certificate
$sOidKerberosAuthentication = "1.3.6.1.5.2.3.5"
$CandidateCerts = @(dir cert:\LocalMachine\My | ? { $_.HasPrivateKey -and ( ( ($_.EnhancedKeyUsageList | ? { $_.ObjectId -eq $sOidKerberosAuthentication }) -ne $null) -OR ($_.Extensions| ? {$_.EnhancedKeyUsages | ? {$_.Value -eq $sOidKerberosAuthentication} } ) ) })
Write-Debug "There are $($CandidateCerts.Length) certificates for Kerberos Authentication"
"There are $($CandidateCerts.Length) certificates for Kerberos Authentication"| Out-File $LogFile -Append -Encoding unicode
$ValidCandidateCerts = @($CandidateCerts | ? { $_.Verify() })
Write-Debug "Of these Kerberos Authentication certificates, $($ValidCandidateCerts.Length) are valid"
"Of these Kerberos Authentication certificates, $($ValidCandidateCerts.Length) are valid"| Out-File $LogFile -Append -Encoding unicode

# If multiple suitable certificates are found, use the one that expires last
$cert = $ValidCandidateCerts | Sort NotAfter -Descending | Select -First 1

if ($null -eq $cert) {
    Write-Information "No valid Kerberos Authentication certificate found. Requesting a new certificate."
    "No valid Kerberos Authentication certificate found. Requesting a new certificate."| Out-File $LogFile -Append -Encoding unicode
    exit RequestNewDCCertificate($SCEPURL, $SCEPChallenge)
}
else {
    $remainingValidity = $cert.NotAfter.Subtract([DateTime]::UtcNow)

    if ( (New-TimeSpan -Days $ValidityThreshold) -ge $remainingValidity) {
        Write-Information "Lifetime of the existing Kerberos Authentication certificate is below the threshold; Requesting a new certificate." 
        "Lifetime of the existing Kerberos Authentication certificate is below the threshold; Requesting a new certificate."| Out-File $LogFile -Append -Encoding unicode
        exit RequestNewDCCertificate($SCEPURL, $SCEPChallenge)
    }
    else {
        Write-Information "$($cert.Thumbprint)`n$($cert.Subject)`n$($cert.Issuer)`n$($cert.NotAfter)"
        $cert| select Thumbprint,Subject,Issuer,NotAfter| fl| Out-File $LogFile -Append -Encoding unicode
        Write-Information "There is an existing, valid Kerberos Authentication certificate with sufficient remaining lifetime." 
        "There is an existing, valid Kerberos Authentication certificate with sufficient remaining lifetime."| Out-File $LogFile -Append -Encoding unicode
        exit 0
    }
}