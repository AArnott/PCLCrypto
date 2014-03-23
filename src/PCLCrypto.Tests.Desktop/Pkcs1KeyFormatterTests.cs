namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using PCLCrypto.Formatters;
    using PCLTesting;

    [TestClass]
    public class Pkcs1KeyFormatterTests
    {
        [TestMethod]
        public void Pkcs1DecodingTest()
        {
            // Initialize the "Known Good" RSAParameters.
            byte[] capi1Blob = Convert.FromBase64String(AsymmetricKeyAlgorithmProviderTests.PrivateKeyFormatsAndBlobs[CryptographicPrivateKeyBlobType.Capi1PrivateKey]);
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportCspBlob(capi1Blob);
            RSAParameters rsaCapi = rsa.ExportParameters(true);

            // Now load up the tested one.
            byte[] pkcs1KeyBlob = Convert.FromBase64String(AsymmetricKeyAlgorithmProviderTests.PrivateKeyFormatsAndBlobs[CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey]);
            RSAParameters homeReadPkcs1 = KeyFormatter.Pkcs1.Read(pkcs1KeyBlob);

            Assert.AreEqual(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.Modulus), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.Modulus), "Modulus");
            Assert.AreEqual(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.Exponent), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.Exponent), "Exponent");
            Assert.AreEqual(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.D), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.D), "D");
            Assert.AreEqual(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.P), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.P), "P");
            Assert.AreEqual(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.Q), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.Q), "Q");
            Assert.AreEqual(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.DP), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.DP), "DP");
            Assert.AreEqual(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.DQ), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.DQ), "DQ");
            Assert.AreEqual(WinRTCrypto.CryptographicBuffer.EncodeToHexString(rsaCapi.InverseQ), WinRTCrypto.CryptographicBuffer.EncodeToHexString(homeReadPkcs1.InverseQ), "InverseQ");
        }
    }
}
