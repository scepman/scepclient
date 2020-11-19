using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ScepClient.Oids
{

    /// <summary>
    /// http://www.cisco.com/c/en/us/support/docs/security-vpn/public-key-infrastructure-pki/116167-technote-scep-00.html
    /// </summary>
    public static class Scep
    {

        /// <summary>
        /// 2.16.840.1.113733.1.9.2 scep-messageType - https://tools.ietf.org/html/draft-nourse-scep-23#section-3.1.1.2
        /// </summary>
        public static readonly Oid MessageType = new Oid("2.16.840.1.113733.1.9.2");

        /// <summary>
        /// 2.16.840.1.113733.1.9.5 scep-senderNonce - https://tools.ietf.org/html/draft-nourse-scep-23#section-3.1.1.5
        /// </summary>
        public static readonly Oid SenderNonce = new Oid("2.16.840.1.113733.1.9.5");

        /// <summary>
        /// 2.16.840.1.113733.1.9.7 scep-transId - https://tools.ietf.org/html/draft-nourse-scep-23#section-3.1.1.1
        /// </summary>
        public static readonly Oid TransactionId = new Oid("2.16.840.1.113733.1.9.7");

        /// <summary>
        /// 2.16.840.1.113733.1.9.6 scep-recipientNonce - Response only
        /// </summary>
        public static readonly Oid RecipientNonce = new Oid("2.16.840.1.113733.1.9.6");

        /// <summary>
        /// 2.16.840.1.113733.1.9.3 scep-pkiStatus - Response only
        /// </summary>
        public static readonly Oid PkiStatus = new Oid("2.16.840.1.113733.1.9.3");

        /// <summary>
        /// 2.16.840.1.113733.1.9.4 scep-failInfo - Failure only
        /// </summary>
        public static readonly Oid FailInfo = new Oid("2.16.840.1.113733.1.9.4");

        /// <summary>
        /// 2.16.840.1.113733.1.9.8 scep-extensionReq
        /// </summary>
        public static readonly Oid ExtensionReq = new Oid("2.16.840.1.113733.1.9.8");

    }

    public static class Pkcs7
    { 
        /// <summary>
        /// 1.2.840.113549.1.7.6 - encryptedData - http://www.alvestrand.no/objectid/1.2.840.113549.1.7.6.html
        /// </summary>
        public static readonly Oid EncryptedData = new Oid("1.2.840.113549.1.7.6", "envelopedData");

    }

    public static class Pkcs
    {
        /// <summary>
        /// 1.2.840.113549.2.5 - digestAlorithm - http://www.alvestrand.no/objectid/1.2.840.113549.2.5.html
        /// </summary>
        public static readonly Oid MD5 = new Oid("1.2.840.113549.2.5", "digestAlgorithm");
    }

}