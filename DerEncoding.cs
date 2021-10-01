using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ScepClient
{

    /// <summary>
    /// Encodes data using ASN.1 DER: https://msdn.microsoft.com/en-us/library/windows/desktop/bb648640%28v=vs.85%29.aspx
    /// The ASN.1 type System defines data types used for the fields within the ASN.1 requests: https://msdn.microsoft.com/en-us/library/windows/desktop/bb540789%28v=vs.85%29.aspx
    /// For the purposes of this SCEP client I have used the DER type encoding in which most of the basic ASN.1 types are encoded as 'TLV' triplets:
    ///     * Tag    - The first byte is the type identifier
    ///     * Length - The second byte defines the length of the data
    ///     * Value  - The remaining bytes hold the encoded data
    /// There are more rules to the type system, such as for handling booleans, integral numbers greater than 255 or large strings, but I have not yet run into the need to handle these
    /// during this PoC work.
    /// </summary>
    public static class DerEncoding
    {

        /// <summary>
        /// PrintableString: https://msdn.microsoft.com/en-us/library/windows/desktop/bb540812%28v=vs.85%29.aspx
        /// </summary>
        public static byte[] EncodePrintableString(string data)
        {
            var dataBytes = Encoding.ASCII.GetBytes(data);

            return getDerBytes(0x13, dataBytes);
        }

        /// <summary>
        /// Integer: https://msdn.microsoft.com/en-us/library/windows/desktop/bb540806%28v=vs.85%29.aspx
        /// </summary>
        public static byte[] EncodeInteger(int data)
        {
            if (data > byte.MaxValue)
            {
                throw new NotSupportedException("Support for integers greater than 255 not yet implemented.");
            }

            var dataBytes = new byte[] { (byte)data };
            return getDerBytes(0x02, dataBytes);
        }

        /// <summary>
        /// Octet: https://msdn.microsoft.com/en-us/library/windows/desktop/bb648644%28v=vs.85%29.aspx
        /// </summary>
        public static byte[] EncodeOctet(byte[] data)
        {
            return getDerBytes(0x04, data);
        }

        private static byte[] getDerBytes(int tag, byte[] data)
        {
            if (data.Length > byte.MaxValue)
            {
                throw new NotSupportedException("Support for integers greater than 255 not yet implemented.");
            }

            var header = new byte[] { (byte)tag, (byte)data.Length };
            return header.Concat(data).ToArray();
        }
    }
}
