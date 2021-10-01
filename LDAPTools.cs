using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace ScepClient
{
    public static class LDAPTools
    {
        #region LDAP RDN Escape code from https://stackoverflow.com/questions/1433383/net-ldap-paths-utilities-c
        #region Constants
        public const int ERROR_SUCCESS = 0;
        public const int ERROR_BUFFER_OVERFLOW = 111;
        #endregion Constants

        [DllImport("ntdsapi.dll", CharSet = CharSet.Unicode)]
        private static extern int DsQuoteRdnValueW(
            int cUnquotedRdnValueLength,
            string psUnquotedRdnValue,
            ref int pcQuotedRdnValueLength,
            IntPtr psQuotedRdnValue
        );

        public static string QuoteRDN(string rdn)
        {
            if (rdn == null) return null;

            int initialLength = rdn.Length;
            int quotedLength = 0;
            IntPtr pQuotedRDN = IntPtr.Zero;

            int lastError = DsQuoteRdnValueW(initialLength, rdn, ref quotedLength, pQuotedRDN);

            switch (lastError)
            {
                case ERROR_SUCCESS:
                    {
                        return string.Empty;
                    }
                case ERROR_BUFFER_OVERFLOW:
                    {
                        break; //continue
                    }
                default:
                    {
                        throw new Win32Exception(lastError);
                    }
            }

            pQuotedRDN = Marshal.AllocHGlobal(quotedLength * UnicodeEncoding.CharSize);

            try
            {
                lastError = DsQuoteRdnValueW(initialLength, rdn, ref quotedLength, pQuotedRDN);

                switch (lastError)
                {
                    case ERROR_SUCCESS:
                        {
                            return Marshal.PtrToStringUni(pQuotedRDN, quotedLength);
                        }
                    default:
                        {
                            throw new Win32Exception(lastError);
                        }
                }
            }
            finally
            {
                if (pQuotedRDN != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pQuotedRDN);
                }
            }
        }
        #endregion LDAP RDN Escape code from https://stackoverflow.com/questions/1433383/net-ldap-paths-utilities-c

    }
}
