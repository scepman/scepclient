<# 
enroll-dc-certificate.ps1 Version: 20200922
C. Hannebauer - Glueck & Kanja Consulting AG

Checks whether a usable Kerberos Authentication certificate exists on the client.
When no valid certificate exists or its remaining validity is less than the required threshold (default 2 months),
then a new certificate is requested from the configured SCEP service.

	.PARAMETER SCEPURL
    URL of the SCEP service to request a new certificate from if required.
	
	.PARAMETER SCEPChallenge
    The password used to authenticate the SCEP request

	.PARAMETER ValidityThreshold
    A new certificate is requested if the remaining validity of the existing certificate falls below this threshold

	.EXAMPLE
    .\enroll-dc-certificate.ps1 -SCEPURL https://scepman.azurewebsites.com/dc -SCEPChallenge password123

Changelog:
20200922 - Initial Version

#>
param
( 
[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$false,HelpMessage='URL of the SCEP service')][string]$SCEPURL,
[Parameter(Position=1,Mandatory=$true,ValueFromPipeline=$false,HelpMessage='password used to authenticate the SCEP request')][string]$SCEPChallenge,
[Parameter(Position=2,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='a new certificate is requested if the remaining validity of the existing certificate falls below this threshold')][timespan]$ValidityThreshold
)

function RequestNewDCCertificate($SCEPURL, $SCEPChallenge) {
    ./ScepClient.exe newdccert $SCEPURL $SCEPChallenge
}

# Main
Write-Information "Enroll DC Certificate Version 20200922"

## Search for an appropriate certificate
$sOidKerberosAuthentication = "1.3.6.1.5.2.3.5"
$CandidateCerts = @(dir cert:\LocalMachine\My | ? { $_.HasPrivateKey -and ( ( ($_.EnhancedKeyUsageList | ? { $_.ObjectId -eq $sOidKerberosAuthentication }) -ne $null) -OR ($_.Extensions| ? {$_.EnhancedKeyUsages | ? {$_.Value -eq $sOidSecureEmail} } ) ) })
Write-Debug "There are $($CandidateCerts.Length) certificates for Kerberos Authentication"
$ValidCandidateCerts = @($CandidateCerts | ? { $_.Verify() })
Write-Debug "Of these Kerberos Authentication certificates, $($ValidCandidateCerts.Length) are valid"

# If multiple suitable certificates are found, use the one that expires last
$cert = $ValidCandidateCerts | Sort NotAfter -Descending | Select -First 1

if ($null -eq $cert) {
    Write-Information "No valid Kerberos Authentication certificate found. Requesting a new certificate." 

    RequestNewDCCertificate($SCEPURL, $SCEPChallenge)

    Return 0
}
else {
    $remainingValidity = $cert.NotAfter.Subtract([DateTime]::UtcNow)

    if ($ValidityThreshold -ge $remainingValidity) {
        Write-Information "Lifetime of the existing Kerberos Authentication certificate is below the threshold; Requesting a new certificate." 
        
        RequestNewDCCertificate($SCEPURL, $SCEPChallenge)

        Return 0
    }
    else {
        Write-Information "There is an existing, valid Kerberos Authentication certificate with sufficient remaining lifetime." 

        return 0
    }
}