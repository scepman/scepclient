<#
Powershell script for renewing script using MTLS endpoint using powershell

Could probably done using native powershell commands but the logic was already written in bash using OpenSSL
#>

# Create a CSR
Function RenewCertificateMTLS($Certificate, $Key, $Root, $AppServiceUrl) {
    $TempCSR = New-TemporaryFile
    $TempKEY = New-TemporaryFile
    $TempP7B = New-TemporaryFile
    $TempPEM = New-TemporaryFile
    $TempWGET = New-TemporaryFile
    
    if ($Env:Path -split ";" -contains "C:\Program Files\OpenSSL-Win64\bin") {
        $env:path = $env:path + ";C:\Program Files\OpenSSL-Win64\bin"
    }
    openssl genrsa -out "$TempKEY" 4096
    openssl req -new -key $TempKEY -sha256 -out $TempCSR -subj "/C=US/ST=State/L=Locality/O=Contoso/OU=Unit/CN=Contoso/emailAddress=email@contoso.com"
    
    # possibly remove aliases?
    # Remove-Item alias:curl

    # Create renewed version of certificate.
    # Invoke-RestMethod -Uri "$AppServiceUrl/.well-known/est/simplereenroll" -Method Post -ContentType "application/pkcs10" -InFile $TempCSR -Certificate $Certificate -PrivateKey $Key -CACertificate $Root | Out-File -Append -FilePath $TempP7B
    # Invoke-RestMethod -Uri "$AppServiceUrl/.well-known/est/simplereenroll" -Method Post -ContentType "application/pkcs10" -InFile $TempCSR -Certificate ([System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromCertFile($Certificate)) -CertificateThumbprint $Key -CACertificate $Root | Out-File -Append -FilePath $TempP7B
    # curl -vvv -X POST --data "@$TempCSR" -H "Content-Type: application/pkcs10" --cert coolcert.pem --key coolcert.key --cacert scepman-root.pem "https://app-scepman-csz5hqanxf6cs.azurewebsites.net/.well-known/est/simplereenroll" >> "temp.p7b"
    # curl.exe -X POST --data "@$TempCSR" -H "Content-Type: application/pkcs10" --cert "$Certificate" --key "$Key" --cacert "$Root" "https://app-scepman-csz5hqanxf6cs.azurewebsites.net/.well-known/est/simplereenroll" >> "temp.p7b"
    wget.exe --certificate=$Certificate --private-key=$Key, --ca-certificate=$Root --post-file=$TempCSR --header="Content-Type:application/pkcs10" --no-check-certificate --output-document=$TempWGET "$AppServiceUrl/.well-known/est/simplereenroll"
    # wget.exe --certificate="coolcert.pem" --private-key="coolcert.key" --ca-certificate="scepman-root.pem" --post-file="req.csr" --header="Content-Type:application/pkcs10" --no-check-certificate --output-document="wget" "https://app-scepman-csz5hqanxf6cs.azurewebsites.net/.well-known/est/simplereenroll"
    
    Write-Output "-----BEGIN PKCS7-----" > "$TempP7B"
    Get-Content $TempWGET >> "$TempP7B"
    Write-Output "-----END PKCS7-----" >> "$TempP7B"
    # Convert to UTF8?
    $MyRawString = Get-Content -Raw "$TempP7B"
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines("$TempP7B", $MyRawString, $Utf8NoBomEncoding)
    
    openssl pkcs7 -print_certs -in "$TempP7B" -out "$TempPEM"

    if (-Not ([String]::IsNullOrWhiteSpace((Get-content $TempPEM)))) {
        Copy-Item -Path $TempKEY -Destination $Key
        Copy-Item -Path $TempPEM -Destination $Certificate
    } else {
        Write-Host "Renewal endpoint returned an error"
        exit 1
    }

}

RenewCertificateMTLS -Certificate "coolcert.pem" -Key "coolcert.key" -Root "scepman-root.pem" -AppServiceUrl "https://app-scepman-csz5hqanxf6cs.azurewebsites.net/"