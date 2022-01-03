# scepclient

A .NET SCEP client

Can be used to extend [SCEPman](https://www.scepman.com/) to easily distribute Kerberos Authentication certificates to AD Domain Controllers instead of only certificates for end-user devices.

## Prerequisites

The .NET Core version requires the [.NET Core 3.1 Runtime](https://dotnet.microsoft.com/download/dotnet-core/3.1). You need only the simple runtime, Desktop or ASP.NET may be used, but are not required.

There is also a version for .NET Framework 4.6.2 available that runs directly on Windows Server 2012 R2 and newer.

## Usage

### Domain Controllers

See the [SCEPman documentation](https://glueckkanja.gitbook.io/scepman/scepman-configuration/optional/domain-controller-certificates) for a detailed description of how to request Kerberos Authentication certificates for Domain Controllers.

### Debugging

The sub commands `gennew`, `gennewext`, and `submit` can be used to debug a SCEP service. Just execute scepclient.exe without any parameters to see usage information (and do not get irritated by the exception, it does no harm).

#### Example: gennewext

Create a file dnslist.txt with the following content:

```
servername1.example
servername2.example
servername3.example
```

Create a file keyUsages.txt with the following content:

```
ServerAuth
ClientAuth
```

Execute the following command:

```
ScepClient.exe gennewext http://scepman.server/static SeCrEtPaSSwOrD dnslist.txt keyUsages.txt "Great Server" greatserver.pfx greatserver.cer
```

## License

SCEPClient is available under the [GPL](LICENSE).

SCEPClient contains code from Stephen Roughley (see https://stephenroughley.com/2015/09/22/a-c-net-scep-client/), which is available under the [Unlicense](https://unlicense.org/).

## Contributing

You may write documentation and source code, pull requests are welcome! You need to provide your contributions under some GPL-compatible license.