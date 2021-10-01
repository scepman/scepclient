using System;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;

namespace DotNetCode
{
	internal static class X509Native
	{
		//// Token: 0x060009FF RID: 2559 RVA: 0x00024380 File Offset: 0x00022580
		//[SecuritySafeCritical]
		//internal static bool HasCertificateProperty(SafeCertContextHandle certificateContext, X509Native.CertificateProperty property)
		//{
		//	byte[] pvData = null;
		//	int num = 0;
		//	return X509Native.UnsafeNativeMethods.CertGetCertificateContextProperty(certificateContext, property, pvData, ref num) || Marshal.GetLastWin32Error() == 234;
		//}

		//// Token: 0x06000A00 RID: 2560 RVA: 0x000243B0 File Offset: 0x000225B0
		//[SecuritySafeCritical]
		//internal static SafeNCryptKeyHandle TryAcquireCngPrivateKey(SafeCertContextHandle certificateContext, out CngKeyHandleOpenOptions openOptions)
		//{
		//	int size = IntPtr.Size;
		//	IntPtr handle;
		//	if (X509Native.UnsafeNativeMethods.CertGetCertificateContextProperty(certificateContext, X509Native.CertificateProperty.NCryptKeyHandle, out handle, ref size))
		//	{
		//		openOptions = CngKeyHandleOpenOptions.EphemeralKey;
		//		return new SafeNCryptKeyHandle(handle, certificateContext);
		//	}
		//	openOptions = CngKeyHandleOpenOptions.None;
		//	bool flag = true;
		//	SafeNCryptKeyHandle safeNCryptKeyHandle = null;
		//	RuntimeHelpers.PrepareConstrainedRegions();
		//	try
		//	{
		//		int num = 0;
		//		if (!X509Native.UnsafeNativeMethods.CryptAcquireCertificatePrivateKey(certificateContext, X509Native.AcquireCertificateKeyOptions.AcquireOnlyNCryptKeys, IntPtr.Zero, out safeNCryptKeyHandle, out num, out flag))
		//		{
		//			flag = false;
		//			if (safeNCryptKeyHandle != null)
		//			{
		//				safeNCryptKeyHandle.SetHandleAsInvalid();
		//			}
		//			return null;
		//		}
		//	}
		//	finally
		//	{
		//		if (!flag && safeNCryptKeyHandle != null && !safeNCryptKeyHandle.IsInvalid)
		//		{
		//			SafeNCryptKeyHandle safeNCryptKeyHandle2 = new SafeNCryptKeyHandle(safeNCryptKeyHandle.DangerousGetHandle(), certificateContext);
		//			safeNCryptKeyHandle.SetHandleAsInvalid();
		//			safeNCryptKeyHandle = safeNCryptKeyHandle2;
		//			flag = true;
		//		}
		//	}
		//	return safeNCryptKeyHandle;
		//}

		//// Token: 0x06000A01 RID: 2561 RVA: 0x00024454 File Offset: 0x00022654
		//[SecuritySafeCritical]
		//internal static byte[] GetCertificateProperty(SafeCertContextHandle certificateContext, X509Native.CertificateProperty property)
		//{
		//	byte[] array = null;
		//	int num = 0;
		//	if (!X509Native.UnsafeNativeMethods.CertGetCertificateContextProperty(certificateContext, property, array, ref num))
		//	{
		//		X509Native.ErrorCode lastWin32Error = (X509Native.ErrorCode)Marshal.GetLastWin32Error();
		//		if (lastWin32Error != X509Native.ErrorCode.MoreData)
		//		{
		//			throw new CryptographicException((int)lastWin32Error);
		//		}
		//	}
		//	array = new byte[num];
		//	if (!X509Native.UnsafeNativeMethods.CertGetCertificateContextProperty(certificateContext, property, array, ref num))
		//	{
		//		throw new CryptographicException(Marshal.GetLastWin32Error());
		//	}
		//	return array;
		//}

		//// Token: 0x06000A02 RID: 2562 RVA: 0x000244A8 File Offset: 0x000226A8
		//[SecurityCritical]
		//internal unsafe static T GetCertificateProperty<T>(SafeCertContextHandle certificateContext, X509Native.CertificateProperty property) where T : struct
		//{
		//	byte[] certificateProperty = X509Native.GetCertificateProperty(certificateContext, property);
		//	fixed (byte* ptr = &certificateProperty[0])
		//	{
		//		return (T)((object)Marshal.PtrToStructure(new IntPtr((void*)ptr), typeof(T)));
		//	}
		//}

		// Token: 0x06000A03 RID: 2563 RVA: 0x000244E0 File Offset: 0x000226E0
		[SecurityCritical]
		internal static bool SetCertificateKeyProvInfo(SafeCertContextHandle certificateContext, ref X509Native.CRYPT_KEY_PROV_INFO provInfo)
		{
			return X509Native.UnsafeNativeMethods.CertSetCertificateContextProperty(certificateContext, X509Native.CertificateProperty.KeyProviderInfo, X509Native.CertSetPropertyFlags.None, ref provInfo);
		}

		//// Token: 0x06000A04 RID: 2564 RVA: 0x000244EB File Offset: 0x000226EB
		//[SecurityCritical]
		//internal static bool SetCertificateNCryptKeyHandle(SafeCertContextHandle certificateContext, SafeNCryptKeyHandle keyHandle)
		//{
		//	return X509Native.UnsafeNativeMethods.CertSetCertificateContextProperty(certificateContext, X509Native.CertificateProperty.NCryptKeyHandle, X509Native.CertSetPropertyFlags.CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG, keyHandle);
		//}

		// Token: 0x06000A05 RID: 2565 RVA: 0x000244FB File Offset: 0x000226FB
		[SecuritySafeCritical]
		internal static SafeCertContextHandle DuplicateCertContext(IntPtr context)
		{
			return X509Native.UnsafeNativeMethods.CertDuplicateCertificateContext(context);
		}

		// Token: 0x06000A06 RID: 2566 RVA: 0x00024504 File Offset: 0x00022704
		[SecuritySafeCritical]
		internal static SafeCertContextHandle GetCertificateContext(X509Certificate certificate)
		{
			SafeCertContextHandle result = X509Native.DuplicateCertContext(certificate.Handle);
			GC.KeepAlive(certificate);
			return result;
		}

		// Token: 0x04000756 RID: 1878
		internal const uint X509_ASN_ENCODING = 1U;

		// Token: 0x04000757 RID: 1879
		internal const string szOID_ECC_PUBLIC_KEY = "1.2.840.10045.2.1";

		// Token: 0x04000758 RID: 1880
		internal const int CRYPT_MACHINE_KEYSET = 32;

		// Token: 0x02000357 RID: 855
		[Flags]
		public enum AxlVerificationFlags
		{
			// Token: 0x04000F48 RID: 3912
			None = 0,
			// Token: 0x04000F49 RID: 3913
			NoRevocationCheck = 1,
			// Token: 0x04000F4A RID: 3914
			RevocationCheckEndCertOnly = 2,
			// Token: 0x04000F4B RID: 3915
			RevocationCheckEntireChain = 4,
			// Token: 0x04000F4C RID: 3916
			UrlOnlyCacheRetrieval = 8,
			// Token: 0x04000F4D RID: 3917
			LifetimeSigning = 16,
			// Token: 0x04000F4E RID: 3918
			TrustMicrosoftRootOnly = 32
		}

		// Token: 0x02000358 RID: 856
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_CONTEXT
		{
			// Token: 0x04000F4F RID: 3919
			internal uint dwCertEncodingType;

			// Token: 0x04000F50 RID: 3920
			internal IntPtr pbCertEncoded;

			// Token: 0x04000F51 RID: 3921
			internal uint cbCertEncoded;

			// Token: 0x04000F52 RID: 3922
			internal IntPtr pCertInfo;

			// Token: 0x04000F53 RID: 3923
			internal IntPtr hCertStore;
		}

		// Token: 0x02000359 RID: 857
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_PUBLIC_KEY_INFO
		{
			// Token: 0x04000F54 RID: 3924
			internal X509Native.CRYPT_ALGORITHM_IDENTIFIER Algorithm;

			// Token: 0x04000F55 RID: 3925
			internal X509Native.CRYPT_BIT_BLOB PublicKey;
		}

		// Token: 0x0200035A RID: 858
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CERT_INFO
		{
			// Token: 0x04000F56 RID: 3926
			internal uint dwVersion;

			// Token: 0x04000F57 RID: 3927
			internal X509Native.CRYPTOAPI_BLOB SerialNumber;

			// Token: 0x04000F58 RID: 3928
			internal X509Native.CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;

			// Token: 0x04000F59 RID: 3929
			internal X509Native.CRYPTOAPI_BLOB Issuer;

			// Token: 0x04000F5A RID: 3930
			internal System.Runtime.InteropServices.ComTypes.FILETIME NotBefore;

			// Token: 0x04000F5B RID: 3931
			internal System.Runtime.InteropServices.ComTypes.FILETIME NotAfter;

			// Token: 0x04000F5C RID: 3932
			internal X509Native.CRYPTOAPI_BLOB Subject;

			// Token: 0x04000F5D RID: 3933
			internal X509Native.CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;

			// Token: 0x04000F5E RID: 3934
			internal X509Native.CRYPT_BIT_BLOB IssuerUniqueId;

			// Token: 0x04000F5F RID: 3935
			internal X509Native.CRYPT_BIT_BLOB SubjectUniqueId;

			// Token: 0x04000F60 RID: 3936
			internal uint cExtension;

			// Token: 0x04000F61 RID: 3937
			internal IntPtr rgExtension;
		}

		// Token: 0x0200035B RID: 859
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CRYPT_ALGORITHM_IDENTIFIER
		{
			// Token: 0x04000F62 RID: 3938
			[MarshalAs(UnmanagedType.LPStr)]
			internal string pszObjId;

			// Token: 0x04000F63 RID: 3939
			internal X509Native.CRYPTOAPI_BLOB Parameters;
		}

		// Token: 0x0200035C RID: 860
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CRYPT_BIT_BLOB
		{
			// Token: 0x04000F64 RID: 3940
			internal uint cbData;

			// Token: 0x04000F65 RID: 3941
			internal IntPtr pbData;

			// Token: 0x04000F66 RID: 3942
			internal uint cUnusedBits;
		}

		// Token: 0x0200035D RID: 861
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct CRYPTOAPI_BLOB
		{
			// Token: 0x04000F67 RID: 3943
			internal uint cbData;

			// Token: 0x04000F68 RID: 3944
			internal IntPtr pbData;
		}

		// Token: 0x0200035E RID: 862
		internal enum AcquireCertificateKeyOptions
		{
			// Token: 0x04000F6A RID: 3946
			None,
			// Token: 0x04000F6B RID: 3947
			AcquireOnlyNCryptKeys = 262144
		}

		// Token: 0x0200035F RID: 863
		internal enum CertificateProperty
		{
			// Token: 0x04000F6D RID: 3949
			KeyProviderInfo = 2,
			// Token: 0x04000F6E RID: 3950
			KeyContext = 5,
			// Token: 0x04000F6F RID: 3951
			NCryptKeyHandle = 78
		}

		// Token: 0x02000360 RID: 864
		[Flags]
		internal enum CertSetPropertyFlags
		{
			// Token: 0x04000F71 RID: 3953
			CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG = 1073741824,
			// Token: 0x04000F72 RID: 3954
			None = 0
		}

		// Token: 0x02000361 RID: 865
		internal enum ErrorCode
		{
			// Token: 0x04000F74 RID: 3956
			Success,
			// Token: 0x04000F75 RID: 3957
			MoreData = 234
		}

		// Token: 0x02000362 RID: 866
		internal struct CRYPT_KEY_PROV_INFO
		{
			// Token: 0x04000F76 RID: 3958
			[MarshalAs(UnmanagedType.LPWStr)]
			internal string pwszContainerName;

			// Token: 0x04000F77 RID: 3959
			[MarshalAs(UnmanagedType.LPWStr)]
			internal string pwszProvName;

			// Token: 0x04000F78 RID: 3960
			internal int dwProvType;

			// Token: 0x04000F79 RID: 3961
			internal int dwFlags;

			// Token: 0x04000F7A RID: 3962
			internal int cProvParam;

			// Token: 0x04000F7B RID: 3963
			internal IntPtr rgProvParam;

			// Token: 0x04000F7C RID: 3964
			internal int dwKeySpec;
		}

		// Token: 0x02000363 RID: 867
		//[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
		//public struct AXL_AUTHENTICODE_SIGNER_INFO
		//{
		//	// Token: 0x04000F7D RID: 3965
		//	public int cbSize;

		//	// Token: 0x04000F7E RID: 3966
		//	public int dwError;

		//	// Token: 0x04000F7F RID: 3967
		//	public CapiNative.AlgorithmId algHash;

		//	// Token: 0x04000F80 RID: 3968
		//	public IntPtr pwszHash;

		//	// Token: 0x04000F81 RID: 3969
		//	public IntPtr pwszDescription;

		//	// Token: 0x04000F82 RID: 3970
		//	public IntPtr pwszDescriptionUrl;

		//	// Token: 0x04000F83 RID: 3971
		//	public IntPtr pChainContext;
		//}

		//// Token: 0x02000364 RID: 868
		//[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
		//public struct AXL_AUTHENTICODE_TIMESTAMPER_INFO
		//{
		//	// Token: 0x04000F84 RID: 3972
		//	public int cbsize;

		//	// Token: 0x04000F85 RID: 3973
		//	public int dwError;

		//	// Token: 0x04000F86 RID: 3974
		//	public CapiNative.AlgorithmId algHash;

		//	// Token: 0x04000F87 RID: 3975
		//	public System.Runtime.InteropServices.ComTypes.FILETIME ftTimestamp;

		//	// Token: 0x04000F88 RID: 3976
		//	public IntPtr pChainContext;
		//}

		// Token: 0x02000365 RID: 869
		[SuppressUnmanagedCodeSecurity]
		[SecurityCritical(SecurityCriticalScope.Everything)]
		[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
		public static class UnsafeNativeMethods
		{
			//// Token: 0x06001B7A RID: 7034
			//[DllImport("clr")]
			//public static extern int _AxlGetIssuerPublicKeyHash(IntPtr pCertContext, out SafeAxlBufferHandle ppwszPublicKeyHash);

			//// Token: 0x06001B7B RID: 7035
			//[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
			//[DllImport("clr")]
			//public static extern int CertFreeAuthenticodeSignerInfo(ref X509Native.AXL_AUTHENTICODE_SIGNER_INFO pSignerInfo);

			//// Token: 0x06001B7C RID: 7036
			//[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
			//[DllImport("clr")]
			//public static extern int CertFreeAuthenticodeTimestamperInfo(ref X509Native.AXL_AUTHENTICODE_TIMESTAMPER_INFO pTimestamperInfo);

			//// Token: 0x06001B7D RID: 7037
			//[DllImport("clr")]
			//public static extern int CertVerifyAuthenticodeLicense(ref CapiNative.CRYPTOAPI_BLOB pLicenseBlob, X509Native.AxlVerificationFlags dwFlags, [In][Out] ref X509Native.AXL_AUTHENTICODE_SIGNER_INFO pSignerInfo, [In][Out] ref X509Native.AXL_AUTHENTICODE_TIMESTAMPER_INFO pTimestamperInfo);

			//// Token: 0x06001B7E RID: 7038
			//[DllImport("crypt32.dll", SetLastError = true)]
			//[return: MarshalAs(UnmanagedType.Bool)]
			//internal static extern bool CertGetCertificateContextProperty(SafeCertContextHandle pCertContext, X509Native.CertificateProperty dwPropId, [MarshalAs(UnmanagedType.LPArray)][Out] byte[] pvData, [In][Out] ref int pcbData);

			//// Token: 0x06001B7F RID: 7039
			//[DllImport("crypt32.dll", SetLastError = true)]
			//[return: MarshalAs(UnmanagedType.Bool)]
			//internal static extern bool CertGetCertificateContextProperty(SafeCertContextHandle pCertContext, X509Native.CertificateProperty dwPropId, out IntPtr pvData, [In][Out] ref int pcbData);

			// Token: 0x06001B80 RID: 7040
			[DllImport("crypt32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			internal static extern bool CertSetCertificateContextProperty(SafeCertContextHandle pCertContext, X509Native.CertificateProperty dwPropId, X509Native.CertSetPropertyFlags dwFlags, [In] ref X509Native.CRYPT_KEY_PROV_INFO pvData);

			//// Token: 0x06001B81 RID: 7041
			//[DllImport("crypt32.dll", SetLastError = true)]
			//[return: MarshalAs(UnmanagedType.Bool)]
			//internal static extern bool CertSetCertificateContextProperty(SafeCertContextHandle pCertContext, X509Native.CertificateProperty dwPropId, X509Native.CertSetPropertyFlags dwFlags, [In] SafeNCryptKeyHandle pvData);

			// Token: 0x06001B82 RID: 7042
			[DllImport("crypt32.dll")]
			internal static extern SafeCertContextHandle CertDuplicateCertificateContext(IntPtr certContext);

			//// Token: 0x06001B83 RID: 7043
			//[DllImport("crypt32.dll", SetLastError = true)]
			//[return: MarshalAs(UnmanagedType.Bool)]
			//internal static extern bool CryptAcquireCertificatePrivateKey(SafeCertContextHandle pCert, X509Native.AcquireCertificateKeyOptions dwFlags, IntPtr pvReserved, out SafeNCryptKeyHandle phCryptProvOrNCryptKey, out int dwKeySpec, [MarshalAs(UnmanagedType.Bool)] out bool pfCallerFreeProvOrNCryptKey);
		}
	}
}
