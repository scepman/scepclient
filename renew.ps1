<#
Powershell script for renewing certificate using MTLS endpoint using powershell

Example use
RenewCertificateMTLS -Certificate "path\to\cert\certificate.pfx" -Password "password-for-private-key" -AppServiceUrl "https://scepman-appservice.net/"
#>

using namespace System.Security.Cryptography.X509Certificates
using namespace System.Security.Authentication
using namespace System.Net.Http
using namespace System.Net.Security


Function RenewCertificateMTLS($Certificate) {
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
    MachineKeySet = TRUE
    SMIME = False
    PrivateKeyArchive = FALSE
    UserProtected = FALSE
    UseExistingKeySet = FALSE
    ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
    ProviderType = 12
    RequestType = PKCS10
    KeyUsage = 0xa0
    
    [EnhancedKeyUsageExtension]
    OID=1.3.6.1.5.5.7.3.1 ; this is for Server Authentication / Token Signing'
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
    CertReq -accept $TempP7B
}

Function GetSCEPmanCerts {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AppServiceUrl,
        [Parameter(Mandatory=$false)]
        [string]$FilterString,
        [Parameter(Mandatory=$false)]
        [string]$ValidityThresholdDays
    )
    
    $rootCaUrl = "$AppServiceUrl/certsrv/mscep/mscep.dll/pkiclient.exe?operation=GetCACert"
    $rootPath = New-TemporaryFile
    Invoke-WebRequest -Uri $rootCaUrl -OutFile $rootPath

    # Load the downloaded certificate
    $rootCert = New-Object X509Certificate2($rootPath)
s
    # Find all certificates in the 'My' stores that are issued by the downloaded certificate
    $certs = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Issuer -eq $rootCert.Issuer }
    $certs += Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object { $_.Issuer -eq $rootCert.Issuer }
    if ($FilterString) {
        $certs = $certs | Where-Object { $_.Subject -Match $FilterString } 
    }
    if (!($ValidityThresholdDays)) {
        $ValidityThresholdDays = 30  # Default is 30 days
    }
    $ValidityThreshold = New-TimeSpan -Days $ValidityThresholdDays
    $certs = $certs | Where-Object { $ValidityThreshold -ge $_.NotAfter.Subtract([DateTime]::UtcNow) }

    $certs | ForEach-Object {
        Write-Output "Found certificate issued by the downloaded certificate:"
        Write-Output "Subject: $($_.Subject)"
        Write-Output "Issuer: $($_.Issuer)"
        Write-Output "Thumbprint: $($_.Thumbprint)"
    }
    return $certs
}

Function RenewSCEPmanCerts {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AppServiceUrl,
        [Parameter(Mandatory=$false)]
        [string]$FilterString,
        [Parameter(Mandatory=$false)]
        [string]$ValidityThresholdDays
    )
    
    # Get all candidate certs
    $certs = GetSCEPmanCerts -AppServiceUrl $AppServiceUrl -FilterString $FilterString -ValidityThresholdDays $ValidityThreshold
    # Renew all certs
    $certs | ForEach-Object { RenewCertificateMTLS -Certificate $_ }
}

GetSCEPmanCerts -AppServiceUrl "https://app-scepman-csz5hqanxf6cs.azurewebsites.net/" -ValidityThresholdDays 100

# RenewCertificateMTLS -Certificate "C:\Users\BenGodwin\OneDrive - glueckkanja-gab\Desktop\scepclient\certificate-test.pfx" -Password "TCR7Mq0Sw3XssyPmmtGIoBlk" -AppServiceUrl "https://app-scepman-csz5hqanxf6cs.azurewebsites.net/"