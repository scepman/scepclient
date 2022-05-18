<#
CreateAndInstallClientCertificates.ps1 Version: 20220518
C. Written by Darragh Ó Héiligh
Heavily inspired from enroll-dc-certificate

Checks whether a usable Client  Authentication certificate exists on the server.
When no valid certificate exists or its remaining validity is less than the required threshold (default 1 month),
then a new certificate is requested from the configured SCEP service.
If file sanlist.txt exists the FQDN's in it will be included into the SubjectAlternativeName attribute. e.g. ldap.acme.net
You must have text files with passwords as secure strings for Tier 0 and Tier 1. 

	.PARAMETER SCEPURL
    URL of the SCEP service to request a new certificate from if required.
	
	.PARAMETER SCEPChallenge
    The password used to authenticate the SCEP request

	.PARAMETER ValidityThreshold
    A new certificate is requested if the remaining validity of the existing certificate falls below this threshold

	.PARAMETER ValidityThresholdDays
    Alternative to ValidityThreshold, where the remaining validity is specified as the number of days

    	.PARAMETER Tier0User
    Following Microsoft tiering policies, the tier 0 user generally only has access to confidential servers labeled as tier 0. 

    .PARAMETER Tier1User
    Following Microsoft tiering policies, the tier 1 user generally only has access to confidential servers labeled as tier 0. 

    .PARAMETER ServerArray
    The server array contains the names of servers ($ServerArray.ServerName) that this script should loop through. 

	.EXAMPLE
    .\enroll-ClientAuthentication-certificate.ps1 -SCEPURL https://scepman.azurewebsites.com/client -SCEPChallenge password123 -Tier0User "Tier0ServiceUser" -Tier1User "Tier1Serviceuser" -ServerArray $ServerArray

#>
param
( 
    [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $false, HelpMessage = 'URL of the SCEP service')][string]$SCEPURL,
    [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline = $false, HelpMessage = 'password used to authenticate the SCEP request')][string]$SCEPChallenge,
    [Parameter(Position = 2, Mandatory = $false, ValueFromPipeline = $false, HelpMessage = 'a new certificate is requested if the remaining validity of the existing certificate falls below this threshold')][timespan]$ValidityThreshold,
    [Parameter(Position = 3, Mandatory = $false, ValueFromPipeline = $false, HelpMessage = 'alternative to ValidityThreshold, where the remaining validity is specified as the number of days')][Int]$ValidityThresholdDays,
    [Parameter(Position = 4, Mandatory = $false, ValueFromPipeline = $false, HelpMessage = "automatically log to a file in the script's directory")][switch]$LogToFile,
    [Parameter(Position = 5, Mandatory = $true, ValueFromPipeline = $false, HelpMessage = "Tier 0 service account username")][string]$Tier0User,
    [Parameter(Position = 6, Mandatory = $true, ValueFromPipeline = $false, HelpMessage = "Tier 1 service account username")][string]$Tier1User,
    [Parameter(Position = 5, Mandatory = $true, ValueFromPipeline = $false, HelpMessage = "Array of Servers in format ServerArray.ServerName")][array]$ServerArray
)

function RequestNewClientAuthenticationCertificate($SCEPURL, $SCEPChallenge, $ServerName, $ServerFQDN) {
    write-output "Requesting certificate for $ServerName" 
    ## Preparing the text file ffor this server. 
    $CerFileName = $ServerName + ".cer"
    $PfxFileName = $ServerFQDN + ".pfx" 
    Out-File -InputObject $ServerFQDN -FilePath dnslist.txt 
    Out-File -InputObject $ServerName -FilePath dnslist.txt -Append
    if (Test-Path -Path './sanlist.txt') {
        # Add SANs if this file exists
        Log-Information "using sanlist.txt for additional SANs"
        $params = @('gennewext', $SCEPURL, $SCEPChallenge, 'sanlist.txt', 'dnslist.txt', 'keyUsages.txt', $ServerFQDN, $PfxFileName, $CerFileName)
    }
    ELSE {
        $params = @('gennewext', $SCEPURL, $SCEPChallenge, 'dnslist.txt', 'keyUsages.txt', $ServerFQDN, $PfxFileName, $CerFileName)
    }
    $errorOutput = $( $output = & './ScepClient.exe' $params ) 2>&1 # Capture error output, see https://stackoverflow.com/a/66861283/4054714

    $exitCode = $LASTEXITCODE

    $output = [string]::Join("`n", $output) # Sometimes $output is an array of the lines. Sometimes it's the whole output. This makes it deterministic.
    Log-Debug $output

    if (0 -eq $exitCode -and $null -eq $errorOutput) {
        Log-Information "Requested a new certificate, Exit Code $exitCode"
    }
    else {
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

Function CreateAndInstallCertificate ($SCEPURL, $SCEPChallenge, $ServerName, $ServerFQDN, $Session, $PFXFileName) {
    # Does what it says on the tin. Cuts out duplication in the main script body. 
    RequestNewClientAuthenticationCertificate -SCEPURL $SCEPURL -SCEPChallenge $SCEPChallenge -ServerName $ServerName -ServerFQDN $ServerFQDN 
    $DestinationFilePath = "c:\windows\temp\$($PFXFileName)"
    Write-Host "In creation and installation function. Working on $Session.ComputerName"
    write-output (Copy-Item -Path $PFXFileName -ToSession $session -Destination $DestinationFilePath)
    invoke-command -Session $Session -ScriptBlock {
        $username = "NotNeeded"
        $pwdTxt = "password" | ConvertTo-SecureString -AsPlainText -Force
        $CertCred = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $pwdTxt
        $CertPath = "c:\windows\temp\$($Using:PFXFileName)"
        write-output $CertPath 
        Write-output $CertCred
        Import-PfxCertificate -FilePath $CertPath -CertStoreLocation Cert:LocalMachine\My -Password $CertCred.Password
    }
}

# Variables e.g. for Logfile
$ScriptFolder = Split-Path -parent $MyInvocation.MyCommand.Definition
$ScriptFullName = $MyInvocation.MyCommand.Name
$ScriptName = ($MyInvocation.MyCommand.Name).Replace(".ps1", "")
$LogFile = "$ScriptFolder\$ScriptName.log"
Set-Location $ScriptFolder # change path to scriptfolder

Log-Information "$(Get-Date) - Enroll ClientAuthentication Certificate Version 20220516"

if (!(Test-Path -Path './ScepClient.exe')) {
    # The current working directory should be where the PS script and ScepClient.exe reside
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

Write-Output "Starting the main processing."
## Itterate through the servers and do the magic of creating and installing certificates if they are needed. 
Try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
Catch {
    Write-Warning $_.Exception.Message
    Read-Host "Script will end. Press enter to close the window"
    Exit
}
    
ForEach ($Server in $ServerArray) {
    $ServerName = $Server.ServerName -replace ".your.fqdn"
    $ServerFQDN = [String] $Server.ServerName
    Write-output "Working on $ServerFQDN  $ServerName" 

    ## We need to pass in different credentials depending on the tier. 
    ## This unusual join statement in the if block below is to account for computers that have names longer than 15 characters. 
    If ([bool] (((Get-ADComputer -Identity (-join $ServerName[0..14]) -properties MemberOf).MemberOf -match "Tier 1") -ne $null) -eq $true) {
        write-output "$Server.ServerName is in Tier 1." 
        $username = $Tier1User
        $pwdTxt = Get-Content "Tier1.txt"
        $securePwd = $pwdTxt | ConvertTo-SecureString 
        $ServerCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $securePwd
    }
    elseIf ([bool] (((Get-ADComputer -Identity (-join $ServerName[0..14]) -properties MemberOf).MemberOf -match "Tier 0") -ne $null) -eq $True) {
        write-output "$ServerFQDN is in Tier 1." 
        $username = $Tier0User
        $pwdTxt = Get-Content "Tier0.txt"
        $securePwd = $pwdTxt | ConvertTo-SecureString 
        $ServerCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $securePwd
    }
    else {
        write-output "Server not in expected group"
    }

    ## Establish a session with the remote server. 
    $session = New-PSSession -ComputerName $ServerName -Credential $ServerCredentials
       
    ## Search for an appropriate certificate
    ## The below line made my brain explode. It wraps a nested where statement to check through the EnhancedKeyUsageList.
    ## To keep things interesting, I'm getting the cert from the remote server then doing all of the checks locally. 
    $CandidateCerts = @(invoke-command -Session $session -ScriptBlock { get-childitem cert:localmachine\my | ? { $_.HasPrivateKey -and $_.Issuer -match "Scepman" -and ((($_.EnhancedKeyUsageList | ? { $_.FriendlyName -eq "Client Authentication" }) -ne $null)) } })
        
    Log-Debug "There are $($CandidateCerts.Length) certificates for Client Authentication"
    Write-Output "There are $($CandidateCerts.Length) certificates for client  Authentication on $ServerFQDN"
    $ValidCandidateCerts = @($CandidateCerts | ? { $_.Verify() })
    Log-Debug "Of these Kerberos Authentication certificates, $($ValidCandidateCerts.Length) are valid"
    Write-Output "Of these Kerberos Authentication certificates, $($ValidCandidateCerts.Length) are valid on $ServerFQDN"

    # If multiple suitable certificates are found, use the one that expires last
    $cert = $ValidCandidateCerts | Sort NotAfter -Descending | Select -First 1

    ## Setting variables ready for copying. 
    $HostPath = "\\$($($ServerName))\c$\windows\temp\"
    $PfxFileName = $ServerFQDN + ".pfx" 

    if ($null -eq $cert) {
        Log-Information "No valid Client Authentication certificate found. Requesting a new certificate."
        Write-Output "No valid Client Authentication certificate found. Requesting a new certificate. on $ServerFQDN"
        CreateAndInstallCertificate -SCEPURL $SCEPURL -SCEPChallenge $SCEPChallenge -ServerName $ServerName -ServerFQDN $ServerFQDN -Session $Session -PFXFileName $PFXFileName
    }
    else {
        $remainingValidity = $cert.NotAfter.Subtract([DateTime]::UtcNow)

        if ($ValidityThreshold -ge $remainingValidity) {
            Log-Information "Lifetime of the existing Client Authentication certificate is below the threshold; Requesting a new certificate." 
            Write-Output "Lifetime of the existing Client Authentication certificate is below the threshold; Requesting a new certificate on $ServerFQDN" 
            CreateAndInstallCertificate -SCEPURL $SCEPURL -SCEPChallenge $SCEPChallenge -ServerName $ServerName -ServerFQDN $ServerFQDN -Session $Session -PFXFileName $PFXFileName
        }
        else {
            Log-Information "There is an existing, valid Client Authentication certificate with sufficient remaining lifetime:`r`nThumbprint: $($cert.Thumbprint)`r`nSubject: $($cert.Subject)`r`nIssuer: $($cert.Issuer)`r`nExpiration: $($cert.NotAfter)" 
            Write-Output "There is an existing, valid Client Authentication certificate with sufficient remaining lifetime:`r`nThumbprint: $($cert.Thumbprint)`r`nSubject: $($cert.Subject)`r`nIssuer: $($cert.Issuer)`r`nExpiration: $($cert.NotAfter) on $ServerFQDN" 
        }
    }
    Remove-PSSession $session
}