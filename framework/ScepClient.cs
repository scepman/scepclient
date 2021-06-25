using System;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Security.Cryptography.Pkcs;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Asn1;
using System.Collections.Generic;
using Org.BouncyCastle.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using Org.BouncyCastle.Cms;
using System.DirectoryServices.ActiveDirectory;
using Org.BouncyCastle.Pkcs;
using BCPkcs = Org.BouncyCastle.Asn1.Pkcs;
using AsnX509 = Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using System.DirectoryServices;
using Org.BouncyCastle.Asn1.X509;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;
using DotNetCode;

namespace ScepClient
{
    class ScepClient
    {
        enum Command { gennew, submit, newdccert };

        public static void Main(string[] args)
        {
            Console.WriteLine("SCEPClient");
            Console.WriteLine("2020 by Glueck & Kanja, based on https://stephenroughley.com/2015/09/22/a-c-net-scep-client/");
            Console.WriteLine();
            Console.WriteLine("Usage: ScepClient.exe <command> <URL> <further parameters...>");
            Console.WriteLine();
            Console.WriteLine("Generate a new key and submit (debug only):");
            Console.WriteLine("ScepClient.exe gennew <URL> <PFXOutputPath> <CertOutputPath> [PKCS10OutputPath] [SCEPChallengePassword] [CN]");
            Console.WriteLine("Example: ScepClient gennew http://ADCS_HOST/certsrv/mscep/mscep.dll newcert.pfx newcert.cer");
            Console.WriteLine();
            Console.WriteLine("Enroll for a new Domain Controller certificate:");
            Console.WriteLine("ScepClient.exe newdccert <URL> challengePassword [Pkcs12DebugOutputPath]");
            Console.WriteLine("Example: ScepClient newdccert http://scepman-1234.azurewebsites.com/dc password123");
            Console.WriteLine();
            Console.WriteLine("Submit an existing request (debug only):");
            Console.WriteLine("ScepClient.exe submit <URL> <RequestKeyPFX> <RequestPath> <CertOutputPath>");
            Console.WriteLine("Example: ScepClient submit http://ADCS_HOST/certsrv/mscep/mscep.dll requestkey.pfx request.req newcert.cer");
            Console.WriteLine();

            Command currentCommand;
            Enum.TryParse<Command>(args[0], out currentCommand);
            string scepURL = args[1];

            switch(currentCommand)
            {
                case Command.newdccert:
                    GenerateComputerCertificateRequest(scepURL, args[2], args.Length > 3 ? args[3] : null);
                    break;
                case Command.gennew:
                    GenerateNew(
                        scepURL,    // SCEP URL
                        args[2],    // PFX path
                        args[3],    // CER path
                        args.Length > 4 ? args[4] : null,       // PKCS#10OutputPath
                        args.Length > 5 ? args[5] : "password", // Challenge Password
                        args.Length > 6 ? args[6] : null        // CN of certificate
                    );
                    break;
                case Command.submit:
                    SubmitExistingPkcs10(scepURL, args[2], args[3], args[4]);
                    break;
                default:
                    throw new NotImplementedException($"Command {currentCommand} is not implemented!");
            }
        }

        private static string _passwordForTemporaryKeys;
        private static string PasswordForTemporaryKeys
        {
            get
            {
                if (null == _passwordForTemporaryKeys)
                {
                    byte[] binPw = new byte[40];
                    using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                        rng.GetBytes(binPw);
                    _passwordForTemporaryKeys = Convert.ToBase64String(binPw);
                }

                return _passwordForTemporaryKeys;
            }
        }

        private static void SubmitExistingPkcs10(string scepURL, string requestPfxPath, string requestPath, string certOutputPath)
        {
            X509Certificate2 selfSignedCert = new X509Certificate2(requestPfxPath, "password");
            byte[] pkcs10 = File.ReadAllBytes(requestPath);

            byte[] binIssuedCert = SubmitPkcs10ToScep(scepURL, pkcs10, selfSignedCert);
            File.WriteAllBytes(certOutputPath, binIssuedCert);
        }

        private static void GenerateComputerCertificateRequest(string scepURL, string challengePassword, string outputPath)
        {
            bool useDebugOutput = !string.IsNullOrEmpty(outputPath);
            string pfxPassword = useDebugOutput ? "password" : PasswordForTemporaryKeys;

            AsymmetricCipherKeyPair rsaKeyPair = GenerateRSAKeyPair(2048);

            Pkcs10CertificationRequest request = CreatePKCS10ForComputer(challengePassword, rsaKeyPair);

            byte[] pkcs10 = request.GetDerEncoded();

            X509Certificate selfSignedCertBC = SignCertificateFromRequest(request, new Asn1SignatureFactory("SHA256WITHRSA", rsaKeyPair.Private));

            byte[] baSelfSignedCert = SaveAsPkcs12(selfSignedCertBC, rsaKeyPair, PasswordForTemporaryKeys);

            byte[] binIssuedCert;

            using (X509Certificate2 selfSignedCert = new X509Certificate2(baSelfSignedCert, PasswordForTemporaryKeys))
                binIssuedCert = SubmitPkcs10ToScep(scepURL, pkcs10, selfSignedCert);

            X509Certificate bcIssuedCert = new X509CertificateParser().ReadCertificate(binIssuedCert);
            byte[] issuedPkcs12 = SaveAsPkcs12(bcIssuedCert, rsaKeyPair, pfxPassword);
            if (useDebugOutput)
                File.WriteAllBytes(outputPath, issuedPkcs12);

            ImportPFX2MachineStore(useDebugOutput, pfxPassword, issuedPkcs12);
        }

        /// <summary>
        /// Import the certificate with private key to the machine MY store while force using Software KSP.
        /// 
        /// See https://stackoverflow.com/questions/51522330/c-sharp-import-certificate-and-key-pfx-into-cng-ksp
        /// </summary>
        private static void ImportPFX2MachineStore(bool useDebugOutput, string pfxPassword, byte[] issuedPkcs12)
        {
            using X509Certificate2 issuedCertificateAndPrivate = new X509Certificate2(issuedPkcs12, pfxPassword, X509KeyStorageFlags.Exportable);
            RSACng keyFromPFx = new RSACng();
            keyFromPFx.FromXmlString(issuedCertificateAndPrivate.GetRSAPrivateKey().ToXmlString(true));
            var keyData = keyFromPFx.Key.Export(CngKeyBlobFormat.GenericPrivateBlob);
            var keyParams = new CngKeyCreationParameters
            {
                ExportPolicy = useDebugOutput ? CngExportPolicies.AllowPlaintextExport : CngExportPolicies.None,
                KeyCreationOptions = CngKeyCreationOptions.MachineKey,
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider
            };
            keyParams.Parameters.Add(new CngProperty(CngKeyBlobFormat.GenericPrivateBlob.Format, keyData, CngPropertyOptions.None));
            CngKey key = CngKey.Create(CngAlgorithm.Rsa, $"KDC-Key-{issuedCertificateAndPrivate.Thumbprint}", keyParams);

            X509Certificate2 certWithCNGKey = new X509Certificate2(issuedCertificateAndPrivate.Export(X509ContentType.Cert));
            certWithCNGKey = certWithCNGKey.CopyWithPersistedCngKeyFixed(key);
            using X509Store storeLmMy = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            storeLmMy.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            storeLmMy.Add(certWithCNGKey);
            storeLmMy.Close();
        }

        private static Pkcs10CertificationRequest CreatePKCS10ForComputer(string challengePassword, AsymmetricCipherKeyPair rsaKeyPair)
        {
            //            GenerateSelfSignedCertificate("CN=" + LDAPTools.QuoteRDN(fqdn), out RSA algRSA, out CertificateRequest req, out X509Certificate2 selfSignedCert);

            AsnX509.X509ExtensionsGenerator extensions = new AsnX509.X509ExtensionsGenerator();

            ISet<string> sanDNSCollection = new HashSet<string>();

            string hostName = Dns.GetHostName();
            sanDNSCollection.Add(hostName);
            string fqdn = Dns.GetHostEntry(hostName).HostName;
            sanDNSCollection.Add(fqdn);

#if !DEBUG
            Domain computerDomain = Domain.GetComputerDomain();
            sanDNSCollection.Add(computerDomain.Name);

            string NetBIOSDomain = GetNetbiosDomainName(computerDomain.Name);
            if (!string.IsNullOrEmpty(NetBIOSDomain))
                sanDNSCollection.Add(NetBIOSDomain);
#endif // !DEBUG


            GeneralNames subjectAlternateNames = new GeneralNames(
                sanDNSCollection
                    .Select(dnsName => new GeneralName(GeneralName.DnsName, dnsName))
                    .ToArray()
                );

            extensions.AddExtension(X509Extensions.SubjectAlternativeName, false, subjectAlternateNames);


            BCPkcs.AttributePkcs extensionRequest = new BCPkcs.AttributePkcs(BCPkcs.PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions.Generate()));

            BCPkcs.AttributePkcs attrPassword = new BCPkcs.AttributePkcs(BCPkcs.PkcsObjectIdentifiers.Pkcs9AtChallengePassword, new DerSet(new DerPrintableString(challengePassword)));

            Pkcs10CertificationRequest request = new Pkcs10CertificationRequest(
                "SHA256WITHRSA",
                new AsnX509.X509Name(new DerObjectIdentifier[] { AsnX509.X509Name.CN }, new string[] { fqdn }),
                rsaKeyPair.Public,
                new DerSet(extensionRequest, attrPassword),
                rsaKeyPair.Private
            );
            return request;
        }

        /// <summary>
        /// Adapted from MethodMan's https://stackoverflow.com/a/13814584/4054714
        /// </summary>
        /// <param name="dnsDomainName">The fully qualified DNS Domain Name</param>
        /// <returns>The NetBIOS name of the domain</returns>
        private static string GetNetbiosDomainName(string dnsDomainName)
        {
            DirectoryEntry rootDSE = new DirectoryEntry($"LDAP://{dnsDomainName}/RootDSE");

            string configurationNamingContext = rootDSE.Properties["configurationNamingContext"][0].ToString();

            DirectoryEntry searchRoot = new DirectoryEntry($"LDAP://{dnsDomainName}/cn=Partitions,{configurationNamingContext}");

            DirectorySearcher searcher = new DirectorySearcher(searchRoot);
            searcher.SearchScope = SearchScope.OneLevel;
            searcher.PropertiesToLoad.Add("netbiosname");
            searcher.Filter = $"(&(objectcategory=Crossref)(dnsRoot={dnsDomainName})(netBIOSName=*))";

            SearchResult result = searcher.FindOne();

            return result?.Properties["netbiosname"][0].ToString();
        }

        private static byte[] SaveAsPkcs12(X509Certificate selfSignedCertBC, AsymmetricCipherKeyPair rsaKeyPair, string password)
        {
            MemoryStream p12Stream = new MemoryStream();
            Pkcs12Store selfSignedExport = new Pkcs12Store();
            selfSignedExport.SetKeyEntry("FirstKey", new AsymmetricKeyEntry(rsaKeyPair.Private), new X509CertificateEntry[] { new X509CertificateEntry(selfSignedCertBC) });
            selfSignedExport.Save(p12Stream, password.ToCharArray(), new SecureRandom());
            byte[] baSelfSignedCert = p12Stream.ToArray();
            return baSelfSignedCert;
        }

        private static X509Certificate SignCertificateFromRequest(Pkcs10CertificationRequest request, ISignatureFactory signer)
        {
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

            DateTime now = DateTime.Now;

            certGen.SetIssuerDN(request.GetCertificationRequestInfo().Subject);
            certGen.SetSubjectDN(request.GetCertificationRequestInfo().Subject);
            certGen.SetNotAfter(now.AddDays(7));
            certGen.SetNotBefore(now.AddMinutes(-10));
            certGen.SetSerialNumber(new Org.BouncyCastle.Math.BigInteger(80, new Random()));
            certGen.SetPublicKey(request.GetPublicKey());

            return certGen.Generate(signer);
        }

        /// <summary>
        /// Generates an RSA key pair.
        /// Source: https://stackoverflow.com/questions/23056347/creating-rsa-public-private-key-pair-with-bouncy-castle-or-net-rsacryptoservice
        /// </summary>
        private static AsymmetricCipherKeyPair GenerateRSAKeyPair(int keySize)
        {
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            SecureRandom secureRandom = new SecureRandom(randomGenerator);
            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(secureRandom, keySize);

            RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }


        private static Pkcs10CertificationRequest CreatePKCS10(string sCN, string challengePassword, AsymmetricCipherKeyPair rsaKeyPair)
        {
             BCPkcs.AttributePkcs attrPassword = new BCPkcs.AttributePkcs(BCPkcs.PkcsObjectIdentifiers.Pkcs9AtChallengePassword, new DerSet(new DerPrintableString(challengePassword)));

            Pkcs10CertificationRequest request = new Pkcs10CertificationRequest(
                "SHA256WITHRSA",
                new AsnX509.X509Name(new DerObjectIdentifier[] { AsnX509.X509Name.CN }, new string[] { sCN }),
                rsaKeyPair.Public,
                new DerSet(attrPassword),
                rsaKeyPair.Private
            );
            return request;
        }

        private static void GenerateNew(string scepURL, string pfxOutputPath, string certOutputPath, string pkcs10OutputPath, string challengePassword, string cN = null)
        {
            AsymmetricCipherKeyPair rsaKeyPair = GenerateRSAKeyPair(2048);

            Pkcs10CertificationRequest request = CreatePKCS10(cN ?? Guid.NewGuid().ToString(), challengePassword, rsaKeyPair);

            byte[] pkcs10 = request.GetDerEncoded();
            if (!string.IsNullOrWhiteSpace(pkcs10OutputPath))
                File.WriteAllBytes(pkcs10OutputPath, pkcs10);

            X509Certificate selfSignedCertBC = SignCertificateFromRequest(request, new Asn1SignatureFactory("SHA256WITHRSA", rsaKeyPair.Private));

            byte[] baSelfSignedCert = SaveAsPkcs12(selfSignedCertBC, rsaKeyPair, PasswordForTemporaryKeys);

            byte[] binIssuedCertSCEPResponse;

            using (X509Certificate2 selfSignedCert = new X509Certificate2(baSelfSignedCert, PasswordForTemporaryKeys))
                binIssuedCertSCEPResponse = SubmitPkcs10ToScep(scepURL, pkcs10, selfSignedCert);

            X509Certificate bcIssuedCert = new X509CertificateParser().ReadCertificate(binIssuedCertSCEPResponse);
            File.WriteAllBytes(certOutputPath, bcIssuedCert.GetEncoded());
            byte[] issuedPkcs12 = SaveAsPkcs12(bcIssuedCert, rsaKeyPair, "password");
            File.WriteAllBytes(pfxOutputPath, issuedPkcs12);
        }

        private static byte[] SubmitPkcs10ToScep(string scepURL, byte[] pkcs10, X509Certificate2 signerCert)
        {
            var webClient = new WebClient();

            X509Certificate2Collection caChain = GetScepCaChain(scepURL, webClient);

            var encryptedMessageData = CreateEnvelopedDataPkcs7(pkcs10, caChain);

            var encodedMessage = CreateSignedDataPkcs7(encryptedMessageData, signerCert);

            byte[] data = webClient.UploadData(scepURL, encodedMessage);
            //byte[] data = SubmitRequestToScepWithGET(scepURL, webClient, encodedMessage);

            return ParseScepResponse(caChain, signerCert, data);
        }

        private static X509Certificate2Collection GetScepCaChain(string scepURL, WebClient webClient)
        {
            byte[] caCertData = webClient.DownloadData(string.Concat(scepURL, "?operation=GetCACert&message=ignored"));

            var caCertChain = new X509Certificate2Collection();
            caCertChain.Import(caCertData);

            return caCertChain;
        }

        private static byte[] CreateEnvelopedDataPkcs7(byte[] pkcs10RequestData, X509Certificate2Collection caChain)
        {
            if (caChain.Count == 0)
                throw new ArgumentException("The SCEP service did not provide any certificates for SCEP communication");

            // Find a certificate 
            // - without key usage extension that forbids Key encipherment
            var CertsWithoutKeyUsageExtensionMissingKeyEncipherment = caChain.OfType<X509Certificate2>()
                .Select(cert => new Tuple<X509Certificate2, IEnumerable<X509Extension>>(cert, cert.Extensions.OfType<X509Extension>()))
                .Where(tuple => !tuple.Item2.OfType<X509KeyUsageExtension>().Any(ku => !ku.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment))); // certificates with Key Usage Extension but without Key Encipherment are not possible

            if (!CertsWithoutKeyUsageExtensionMissingKeyEncipherment.Any())
            {
                throw new ArgumentException("The SCEP service provided its certificate, but it is not suitable for SCEP (KeyEncipherment as Key Usage");
            }

            // - that is trusted (trusted root anchor and unrevoked)
            var UsableCerts = CertsWithoutKeyUsageExtensionMissingKeyEncipherment
                .Where(tuple => tuple.Item1.Verify());

            if (!UsableCerts.Any())
            {
                throw new ArgumentException("The SCEP service uses a certificate that is not trusted in this context. Add the CA certificate to the Trusted Root store in Windows.");
            }

            // if possible, use a CA
            X509Certificate2 scepEncryptionCert = UsableCerts
                .SingleOrDefault(tuple => !tuple.Item2.OfType<X509BasicConstraintsExtension>().Any(bc => bc.CertificateAuthority))  // prefer CAs
                ?.Item1;

            if (null == scepEncryptionCert)
                scepEncryptionCert = UsableCerts.First().Item1; // if there is no good CA, we will take the first cert with key encipherment

            //if (null == scepEncryptionCert)
            //    scepEncryptionCert = caChain[0];

            X509CertificateParser x509Parser = new X509CertificateParser();
            X509Certificate certEncryption = x509Parser.ReadCertificate(scepEncryptionCert.Export(X509ContentType.Cert));

            CmsEnvelopedDataGenerator edGen = new CmsEnvelopedDataGenerator();

            edGen.AddKeyTransRecipient(certEncryption);

            CmsProcessable deliveredCertContent = new CmsProcessableByteArray(pkcs10RequestData);
            CmsEnvelopedData envelopedDataResult = edGen.Generate(deliveredCertContent, CmsEnvelopedGenerator.Aes256Cbc);
            return envelopedDataResult.ContentInfo.GetDerEncoded();
        }

        private static byte[] lastSenderNonce;

        private static byte[] CreateSignedDataPkcs7(byte[] encryptedMessageData, X509Certificate2 localPrivateKey)
        {
            // Create the outer envelope, signed with the local private key
            var signer = new CmsSigner(localPrivateKey)
            {
                DigestAlgorithm = Oids.Pkcs.MD5
            };

            // Message Type (messageType): https://tools.ietf.org/html/draft-nourse-scep-23#section-3.1.1.2
            // PKCS#10 request = PKCSReq (19)
            var messageType = new AsnEncodedData(Oids.Scep.MessageType, DerEncoding.EncodePrintableString("19"));
            signer.SignedAttributes.Add(messageType);

            // Tranaction ID (transId): https://tools.ietf.org/html/draft-nourse-scep-23#section-3.1.1.1
            var sha = new SHA512Managed();
            var hashedKey = sha.ComputeHash(localPrivateKey.GetPublicKey());
            var hashedKeyString = Convert.ToBase64String(hashedKey);
            var transactionId = new Pkcs9AttributeObject(Oids.Scep.TransactionId, DerEncoding.EncodePrintableString(hashedKeyString));
            signer.SignedAttributes.Add(transactionId);

            // Sender Nonce (senderNonce): https://tools.ietf.org/html/draft-nourse-scep-23#section-3.1.1.5
            lastSenderNonce = new byte[16];
            RNGCryptoServiceProvider.Create().GetBytes(lastSenderNonce);
            var nonce = new Pkcs9AttributeObject(Oids.Scep.SenderNonce, DerEncoding.EncodeOctet(lastSenderNonce));
            signer.SignedAttributes.Add(nonce);

            // Seems that the oid is not needed for this envelope
            var signedContent = new ContentInfo(encryptedMessageData); //new Oid("1.2.840.113549.1.7.1", "data"), encryptedMessageData);
            var signedMessage = new SignedCms(signedContent);
            signedMessage.ComputeSignature(signer);

            var encodedMessage = signedMessage.Encode();
            return encodedMessage;
        }

        private static byte[] SubmitRequestToScepWithGET(string scepURL, WebClient webClient, byte[] encodedMessage)
        {
            var message = Convert.ToBase64String(encodedMessage);
            var urlEncodedMessage = Uri.EscapeDataString(message);
            byte[] data = webClient.DownloadData(string.Concat(scepURL, "?operation=PKIOperation&message=", urlEncodedMessage));
            return data;
        }

        private static byte[] ParseScepResponse(X509Certificate2Collection caChain, X509Certificate2 ownKey, byte[] data)
        {
            var signedResponse = new SignedCms();
            signedResponse.Decode(data);

            signedResponse.CheckSignature(caChain, true);

            var attributes = signedResponse
                .SignerInfos
                .Cast<SignerInfo>()
                .SelectMany(si => si.SignedAttributes.Cast<CryptographicAttributeObject>());

            AsnEncodedData asnStatus = attributes
                .Single(att => att.Oid.Value == Oids.Scep.PkiStatus.Value)
                .Values[0];
            byte[] baStatusRaw = asnStatus.RawData;
            if (baStatusRaw.Length != 3)        // usually, it is one byte for type, one byte for length and one byte for content
                throw new ArgumentOutOfRangeException($"ASN.1 encoded status has different length than 3, which was expected. ASN content: {asnStatus.Format(false)}");
            byte status = baStatusRaw[2];

            if (status == '2')
            { 
                string failString = string.Empty;
                CryptographicAttributeObject failAttribute = attributes.First(att => att.Oid.Value == Oids.Scep.FailInfo.Value);
                if (null != failAttribute)
                    failString = string.Join(";",
                        failAttribute.Values.OfType<AsnEncodedData>().Select(aed => Convert.ToBase64String(aed.RawData)));
                throw new Exception("There was a Failure when requesting a certificate! FailString(B64): " + failString);
            }

            if (status == '3')
                throw new NotImplementedException("The request status is Pending, which is not yet supported");

            // Any errors then return null
            if (attributes.Any(att => att.Oid.Value == Oids.Scep.FailInfo.Value))
            {
                throw new InvalidOperationException("The status was success, but there was still a FailInfo!");
            }

            var RecipientNonce = attributes
                .Single(att => att.Oid.Value == Oids.Scep.RecipientNonce.Value)
                .Values;
            Asn1InputStream streamRN = new Asn1InputStream(RecipientNonce[0].RawData);
            Asn1OctetString osRN = streamRN.ReadObject() as Asn1OctetString;
            byte[] nextRecipientNonce = osRN.GetOctets();
            if (!nextRecipientNonce.SequenceEqual(lastSenderNonce))
                throw new Exception("Last sender nonce mismatches next recipient nonce!");

            //            return signedResponse.Certificates.OfType<X509Certificate2>().Single(cert => cert.Subject != cert.Issuer).Export(X509ContentType.Cert);

            var envelopedCmsResponse = new EnvelopedCms();
            envelopedCmsResponse.Decode(signedResponse.ContentInfo.Content);
            envelopedCmsResponse.Decrypt(new X509Certificate2Collection(ownKey));

            byte[] binCertificateCollectionResponse = envelopedCmsResponse.ContentInfo.Content;
            return binCertificateCollectionResponse;
        }
    }
}
