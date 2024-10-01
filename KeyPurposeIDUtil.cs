using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Common.Util
{
    public static class KeyPurposeIDUtil
    {
        private static readonly DerObjectIdentifier _documentSigning = new DerObjectIdentifier("1.3.6.1.5.5.7.3.36");

        /// <summary>
        /// Pass a Key Purpose for Extended Key Usage either by name or by OID and get the corresponding BC type KeyPurposeID
        /// </summary>
        public static DerObjectIdentifier ParseKeyPurpose(string keyPurpose)
        {
            // BC doesn't know about Document Signing from RFC 9336 yet
            if (string.Equals(keyPurpose, "document signing", StringComparison.InvariantCultureIgnoreCase)
                || string.Equals(keyPurpose, _documentSigning.Id, StringComparison.InvariantCultureIgnoreCase))
                return _documentSigning;

            keyPurpose = keyPurpose.Replace(" ", string.Empty); // Remove spaces, as they don't appear in the BC KeyPurposeID names
            keyPurpose = keyPurpose.Replace("Authentication", "Auth"); // The abbreviation in BC

            IEnumerable<FieldInfo> knownKeyPurposeFields = typeof(KeyPurposeID).GetFields(BindingFlags.Static | BindingFlags.Public)
                .Where(fieldCandidate => fieldCandidate.FieldType == typeof(KeyPurposeID) && !fieldCandidate.IsDefined(typeof(ObsoleteAttribute), false)); // get known Key Purposes from Bouncy Castle class

            // now match key purposes either by name (partial) or by OID value (exact)
            IEnumerable<FieldInfo> matchingPurposes = knownKeyPurposeFields
                .Where(kpField =>
                kpField.Name.Contains(keyPurpose) ||
                (kpField.GetValue(null)?.ToString().Equals(keyPurpose, StringComparison.InvariantCultureIgnoreCase) ?? false));

            if (matchingPurposes.Any())
            {
                FieldInfo matchingPurpose = matchingPurposes.OrderByDescending(x => x.Name.Length).First();
                return (KeyPurposeID)matchingPurpose?.GetValue(null);
            }
            throw new InvalidOperationException($"Invalid key purpose {keyPurpose}");
        }
    }
}
