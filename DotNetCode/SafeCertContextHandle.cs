using System;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32.SafeHandles;

namespace DotNetCode
{
    internal sealed class SafeCertContextHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        // Token: 0x06000A09 RID: 2569 RVA: 0x00024571 File Offset: 0x00022771
        [SecuritySafeCritical]
        private SafeCertContextHandle() : base(true)
        {
        }

        // Token: 0x06000A0A RID: 2570 RVA: 0x0002457A File Offset: 0x0002277A
        [SecuritySafeCritical]
        internal SafeCertContextHandle(IntPtr handle) : base(true)
        {
            base.SetHandle(handle);
        }

        // Token: 0x17000208 RID: 520
        // (get) Token: 0x06000A0B RID: 2571 RVA: 0x0002458C File Offset: 0x0002278C
        internal static SafeCertContextHandle InvalidHandle
        {
            [SecuritySafeCritical]
            get
            {
                SafeCertContextHandle safeCertContextHandle = new SafeCertContextHandle(IntPtr.Zero);
                GC.SuppressFinalize(safeCertContextHandle);
                return safeCertContextHandle;
            }
        }

        // Token: 0x06000A0C RID: 2572
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertFreeCertificateContext(IntPtr pCertContext);

        // Token: 0x06000A0D RID: 2573 RVA: 0x000245AB File Offset: 0x000227AB
        [SecuritySafeCritical]
        protected override bool ReleaseHandle()
        {
            return SafeCertContextHandle.CertFreeCertificateContext(this.handle);
        }
    }
}
