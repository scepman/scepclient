using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DotNetCode
{
	/// <summary>
	/// This class originates from https://github.com/glueckkanja-pki/TPMImport and where it re-implements .NET code with a fix. It is used here as the relevant code is not availabel on .NET Framework 4.6.2
	/// </summary>
	internal static class CertificateExtensionsCommon
	{
		public static bool IsMachineKey(CngKey cngKey)
		{
			CngProperty propMT = cngKey.GetProperty("Key Type", CngPropertyOptions.None);
			byte[] baMT = propMT.GetValue();
			return (baMT[0] & 0x21) != 0; //  https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers defines NCRYPT_MACHINE_KEY_FLAG as 1 (which the Platform Crypto Provider/TPM uses), but ncrypt.h defines it as 0x20, which is what other providers use
		}

//		[SupportedOSPlatform("windows")]
		[SecurityCritical]
		internal static X509Certificate2 CopyWithPersistedCngKeyFixed(this X509Certificate2 publicCert, CngKey cngKey)
		{
			if (string.IsNullOrEmpty(cngKey.KeyName))
			{
				return null;
			}
			X509Certificate2 x509Certificate = new X509Certificate2(publicCert.RawData);
			CngProvider provider = cngKey.Provider;
			string keyName = cngKey.KeyName;
			bool isMachineKey = IsMachineKey(cngKey);
			int dwKeySpec = CertificateExtensionsCommon.GuessKeySpec(provider, keyName, isMachineKey, cngKey.AlgorithmGroup);
			X509Native.CRYPT_KEY_PROV_INFO crypt_KEY_PROV_INFO = default(X509Native.CRYPT_KEY_PROV_INFO);
			crypt_KEY_PROV_INFO.pwszContainerName = cngKey.KeyName;
			crypt_KEY_PROV_INFO.pwszProvName = cngKey.Provider.Provider;
			crypt_KEY_PROV_INFO.dwFlags = (int)(isMachineKey ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None);
			crypt_KEY_PROV_INFO.dwKeySpec = dwKeySpec;
			using (SafeCertContextHandle certificateContext = X509Native.GetCertificateContext(x509Certificate))
			{
				if (!X509Native.SetCertificateKeyProvInfo(certificateContext, ref crypt_KEY_PROV_INFO))
				{
					int lastWin32Error = Marshal.GetLastWin32Error();
					x509Certificate.Dispose();
					throw new CryptographicException(lastWin32Error);
				}
			}
			return x509Certificate;
		}

		private static int GuessKeySpec(CngProvider provider, string keyName, bool machineKey, CngAlgorithmGroup algorithmGroup)
		{
			if (provider == CngProvider.MicrosoftSoftwareKeyStorageProvider || provider == CngProvider.MicrosoftSmartCardKeyStorageProvider)
			{
				return 0;
			}
			CngKeyOpenOptions openOptions = machineKey ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;
			using (CngKey.Open(keyName, provider, openOptions))
			{
				return 0;
			}
		}

		//private static bool TryGuessKeySpec(CspParameters cspParameters, CngAlgorithmGroup algorithmGroup, out int keySpec)
		//{
		//	if (algorithmGroup == CngAlgorithmGroup.Rsa)
		//	{
		//		return CertificateExtensionsCommon.TryGuessRsaKeySpec(cspParameters, out keySpec);
		//	}
		//	if (algorithmGroup == CngAlgorithmGroup.Dsa)
		//	{
		//		return CertificateExtensionsCommon.TryGuessDsaKeySpec(cspParameters, out keySpec);
		//	}
		//	keySpec = 0;
		//	return false;
		//}

		//private static bool TryGuessRsaKeySpec(CspParameters cspParameters, out int keySpec)
		//{
		//	int[] array = new int[]
		//	{
		//		1,
		//		24,
		//		12,
		//		2
		//	};
		//	foreach (int providerType in array)
		//	{
		//		cspParameters.ProviderType = providerType;
		//		try
		//		{
		//			using (new RSACryptoServiceProvider(cspParameters))
		//			{
		//				keySpec = cspParameters.KeyNumber;
		//				return true;
		//			}
		//		}
		//		catch (CryptographicException)
		//		{
		//		}
		//	}
		//	keySpec = 0;
		//	return false;
		//}

		//private static bool TryGuessDsaKeySpec(CspParameters cspParameters, out int keySpec)
		//{
		//	int[] array = new int[]
		//	{
		//		13,
		//		3
		//	};
		//	foreach (int providerType in array)
		//	{
		//		cspParameters.ProviderType = providerType;
		//		try
		//		{
		//			using (new DSACryptoServiceProvider(cspParameters))
		//			{
		//				keySpec = cspParameters.KeyNumber;
		//				return true;
		//			}
		//		}
		//		catch (CryptographicException)
		//		{
		//		}
		//	}
		//	keySpec = 0;
		//	return false;
		//}
	}
}
