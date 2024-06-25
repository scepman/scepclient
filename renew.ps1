<#
Powershell script for renewing certificate using MTLS endpoint using powershell

Could possibly (?) be done using native powershell commands but the logic was already written in bash using OpenSSL
#>

using namespace System.Security.Cryptography.X509Certificates
using namespace System.Security.Authentication
using namespace System.Net.Http
using namespace System.Net.Security


Function RenewCertificateMTLS($CertificatePath, $AppServiceUrl) {
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

    $body = Get-Content $TempCSR
    # Create new key and CSR
    CertReq -new $TempINF $TempCSR

    # Create renewed version of certificate.
    # Invoke-WebRequest would be easiest option - but doesn't work due to nature of cmd
    # Invoke-WebRequest -Certificate certificate-test.pfx -Body $Body -ContentType "application/pkcs10" -Credential "5hEgpuJQI5afsY158Ot5A87u" -Uri "$AppServiceUrl/.well-known/est/simplereenroll" -OutFile outfile.txt
    # So use HTTPClient instead
    $cert = New-Object X509Certificate2($CertificatePath, "TCR7Mq0Sw3XssyPmmtGIoBlk")
    # write-host for debugging
    Write-Host "Cert Has Private Key: $($cert.HasPrivateKey)"

    $handler = New-Object HttpClientHandler
    $handler.ClientCertificates.Add($cert)
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
    # Convert PKCS7 to PEM
    CertReq -accept $TempP7B

}

RenewCertificateMTLS -Certificate "C:\Users\BenGodwin\OneDrive - glueckkanja-gab\Desktop\scepclient\certificate-test.pfx" -AppServiceUrl "https://app-scepman-csz5hqanxf6cs.azurewebsites.net/"