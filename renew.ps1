<#
Powershell script for renewing certificate using MTLS endpoint using powershell

Example use
RenewCertificateMTLS -Certificate "path\to\cert\certificate.pfx" -AppServiceUrl "https://scepman-appservice.net/"
#>

using namespace System.Security.Cryptography.X509Certificates
using namespace System.Security.Authentication
using namespace System.Net.Http
using namespace System.Net.Security

Function RenewCertificateMTLS() {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate,
        [Parameter(Mandatory=$true)]
        [string]$AppServiceUrl,
        [Parameter(Mandatory=$true, ParameterSetName="User")]
        [switch]$User,
        [Parameter(Mandatory=$true, ParameterSetName="Machine")]
        [switch]$Machine
    )

    if (!$User -and !$Machine) {
        Write-Error "You must specify either -user or -machine."
        return
    }

    $TempCSR = New-TemporaryFile
    $TempP7B = New-TemporaryFile
    $TempINF = New-TemporaryFile
    $url = "$AppServiceUrl/.well-known/est/simplereenroll"

    # In file configuration
    $Inf = 
    '[Version]
    Signature="$Windows NT$"
    
    [NewRequest]
    ;Change to your,country code, company name and common name
    Subject = "C=US, O=Example Co, CN=something.example.com"
    
    KeySpec = 1
    KeyLength = 2048
    Exportable = TRUE
    SMIME = False
    PrivateKeyArchive = FALSE
    UserProtected = FALSE
    UseExistingKeySet = FALSE
    ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
    ProviderType = 12
    RequestType = PKCS10
    KeyUsage = 0xa0'
    if ($Machine) {
        $Inf += "`nMachineKeySet = True" #Command still works without, but cert doesn't appear in store.
    }

    $Inf | Out-File -FilePath $TempINF

    # Create new key and CSR
    CertReq -new $TempINF $TempCSR

    # Create renewed version of certificate.
    # Invoke-WebRequest would be easiest option - but doesn't work due to nature of cmd
    # Invoke-WebRequest -Certificate certificate-test.pfx -Body $Body -ContentType "application/pkcs10" -Credential "5hEgpuJQI5afsY158Ot5A87u" -Uri "$AppServiceUrl/.well-known/est/simplereenroll" -OutFile outfile.txt
    # So use HTTPClient instead
    # write-host for debugging
    Write-Host "Cert Has Private Key: $($Certificate.HasPrivateKey)"

    $handler = New-Object HttpClientHandler
    $handler.ClientCertificates.Add($Certificate)
    $handler.ClientCertificateOptions = [System.Net.Http.ClientCertificateOption]::Manual
    
    $client = New-Object HttpClient($handler)
    $client.HttpClientHandler
    $requestmessage = [System.Net.Http.HttpRequestMessage]::new()
    $body = Get-Content $TempCSR
    $requestmessage.Content = [System.Net.Http.StringContent]::new(
        $body,  
        [System.Text.Encoding]::UTF8,"application/pkcs10"
    )
    $requestmessage.Content.Headers.ContentType = "application/pkcs10"
    $requestmessage.Method = 'POST'
    $requestmessage.RequestUri = $url
    $httpResponseMessage = $client.Send($requestmessage)
    $responseContent =  $httpResponseMessage.Content.ReadAsStringAsync().Result

    Write-Output "-----BEGIN PKCS7-----" > "$TempP7B"
    Write-Output $responseContent >> "$TempP7B"
    Write-Output "-----END PKCS7-----" >> "$TempP7B"
    # Put new certificate into certificate store 
    # (doesn't need to use certreq -submit because that's what the est endpoint is basically doing (submitting to CA))
    CertReq -accept $TempP7B
}

Function GetSCEPmanCerts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AppServiceUrl,
        [Parameter(Mandatory=$true, ParameterSetName="User")]
        [switch]$User,
        [Parameter(Mandatory=$true, ParameterSetName="Machine")]
        [switch]$Machine,
        [Parameter(Mandatory=$false)]
        [string]$FilterString,
        [Parameter(Mandatory=$false)]
        [string]$ValidityThresholdDays
    )

    if (!$User -and !$Machine) {
        Write-Error "You must specify either -user or -machine."
        return
    }
    
    $rootCaUrl = "$AppServiceUrl/certsrv/mscep/mscep.dll/pkiclient.exe?operation=GetCACert"
    $rootPath = New-TemporaryFile
    Invoke-WebRequest -Uri $rootCaUrl -OutFile $rootPath
    if ($?) {
        Write-Information "Root certificate downloaded to $rootPath"
    } else {
        Write-Error "Failed to download root certificate from $rootCaUrl"
        return $null
    }

    # Load the downloaded certificate
    $rootCert = New-Object X509Certificate2($rootPath)

    # Find all certificates in the 'My' stores that are issued by the downloaded certificate
    if ($Machine) {
        $certs = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Issuer -eq $rootCert.Issuer }
        Write-Information "Found $($certs.Count) machine certificates"
    } elseif ($User) {
        $certs = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object { $_.Issuer -eq $rootCert.Issuer }
        Write-Information "Found $($certs.Count) user certificates"
    }

    if (!$certs) {
        Write-Error "No certificates found that are issued by the downloaded certificate."
        return $null
    }

    if ($FilterString) {
        $certs = $certs | Where-Object { $_.Subject -Match $FilterString } 
    }
    if (!($ValidityThresholdDays)) {
        $ValidityThresholdDays = 30  # Default is 30 days
    }
    $ValidityThreshold = New-TimeSpan -Days $ValidityThresholdDays
    $certs = $certs | Where-Object { $ValidityThreshold -ge $_.NotAfter.Subtract([DateTime]::UtcNow) }

    $certs | ForEach-Object {
        Write-Verbose "Found certificate issued by the downloaded certificate:"
        Write-Verbose "Subject: $($_.Subject)"
        Write-Verbose "Issuer: $($_.Issuer)"
        Write-Verbose "Thumbprint: $($_.Thumbprint)"
    }
    return $certs
}

Function RenewSCEPmanCerts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$AppServiceUrl,
        [Parameter(Mandatory=$true, ParameterSetName="User")]
        [switch]$User,
        [Parameter(Mandatory=$true, ParameterSetName="Machine")]
        [switch]$Machine,
        [Parameter(Mandatory=$false)]
        [string]$FilterString,
        [Parameter(Mandatory=$false)]
        [string]$ValidityThresholdDays
    )

    $GetCertsCmd = "GetSCEPmanCerts -AppServiceUrl $AppServiceUrl"
    if ($User) {
        $GetCertsCmd += " -User"
    } elseif ($Machine) {
        $GetCertsCmd += " -Machine"
    } else {
        Write-Error "You must specify either -User or -Machine."
        return
    }
    if ($FilterString) {
        $GetCertsCmd += " -FilterString $FilterString"
    }
    if ($ValidityThresholdDays) {
        $GetCertsCmd += " -ValidityThresholdDays $ValidityThresholdDays"
    }
    
    # Get all candidate certs
    $certs = Invoke-Expression $GetCertsCmd
    # Renew all certs
    $certs | ForEach-Object { 
        if ($User) {
            RenewCertificateMTLS -AppServiceUrl $AppServiceUrl -User -Certificate $_
        } elseif ($Machine) {
            RenewCertificateMTLS -AppServiceUrl $AppServiceUrl -Machine -Certificate $_
        }
    }
}

# $certs = GetSCEPmanCerts -AppServiceUrl "https://app-scepman-csz5hqanxf6cs.azurewebsites.net/" -User -ValidityThresholdDays 1000
# # how to get type of object in powershell?
# Write-Output $certs

# RenewSCEPmanCerts -AppServiceUrl "https://app-scepman-csz5hqanxf6cs.azurewebsites.net/" -ValidityThresholdDays 100

# RenewCertificateMTLS -Certificate $certs[6] -AppServiceUrl "https://app-scepman-csz5hqanxf6cs.azurewebsites.net/" -Machine

# RenewSCEPmanCerts -AppServiceUrl "https://app-scepman-csz5hqanxf6cs.azurewebsites.net/" -User -ValidityThresholdDays 1000 -FilterString "testcert2"