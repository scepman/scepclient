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
    # Also probably add wget to the path?

    # Create new key and CSR
    openssl genrsa -out "$TempKEY" 4096
    openssl req -new -key $TempKEY -sha256 -out $TempCSR -subj "/C=US/ST=State/L=Locality/O=Contoso/OU=Unit/CN=Contoso/emailAddress=email@contoso.com"
    
    # possibly remove aliases?
    # e.g. Remove-Item alias:wget

    # Create renewed version of certificate.
    wget.exe --certificate=$Certificate --private-key=$Key, --ca-certificate=$Root --post-file=$TempCSR --header="Content-Type:application/pkcs10" --no-check-certificate --output-document=$TempWGET "$AppServiceUrl/.well-known/est/simplereenroll"
    Write-Output "-----BEGIN PKCS7-----" > "$TempP7B"
    Get-Content $TempWGET >> "$TempP7B"
    Write-Output "-----END PKCS7-----" >> "$TempP7B"
    # Convert to UTF8? For some reason OpenSSL can't read the text format that PowerShell creates by default.
    $MyRawString = Get-Content -Raw "$TempP7B"
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines("$TempP7B", $MyRawString, $Utf8NoBomEncoding)
    # Convert PKCS7 to PEM
    openssl pkcs7 -print_certs -in "$TempP7B" -out "$TempPEM"

    # If certificates created successfuly, overwrite old certificates
    if (-Not ([String]::IsNullOrWhiteSpace((Get-content $TempPEM)))) {
        Copy-Item -Path $TempKEY -Destination $Key
        Copy-Item -Path $TempPEM -Destination $Certificate
    } else {
        Write-Host "Renewal endpoint returned an error"
        exit 1
    }

}

RenewCertificateMTLS -Certificate "coolcert.pem" -Key "coolcert.key" -Root "scepman-root.pem" -AppServiceUrl "https://app-scepman-csz5hqanxf6cs.azurewebsites.net/"