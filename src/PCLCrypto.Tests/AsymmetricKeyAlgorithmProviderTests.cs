namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Text;
    using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using PCLTesting;

    [TestClass]
    public class AsymmetricKeyAlgorithmProviderTests
    {
        [TestMethod]
        public void OpenAlgorithm_GetAlgorithmName()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            Assert.AreEqual(AsymmetricAlgorithm.RsaOaepSha1, rsa.Algorithm);
        }

        [TestMethod]
        public void CreateKeyPair_InvalidInputs()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            ExceptionAssert.Throws<ArgumentOutOfRangeException>(() =>
                rsa.CreateKeyPair(-1));
            ExceptionAssert.Throws<ArgumentOutOfRangeException>(() =>
                rsa.CreateKeyPair(0));
        }

        [TestMethod]
        public void CreateKeyPair()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            var key = rsa.CreateKeyPair(512);
            Assert.IsNotNull(key);
            Assert.AreEqual(512, key.KeySize);
        }

        [TestMethod]
        public void ImportKeyPair_Null()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            ExceptionAssert.Throws<ArgumentNullException>(
                () => rsa.ImportKeyPair(null));
        }

        [TestMethod]
        public void ImportPublicKey_Null()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            ExceptionAssert.Throws<ArgumentNullException>(
                () => rsa.ImportPublicKey(null));
        }

        [TestMethod]
        public void KeyPairRoundTrip()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            var key = rsa.CreateKeyPair(512);

            int supportedFormats = 0;
            foreach (CryptographicPrivateKeyBlobType format in Enum.GetValues(typeof(CryptographicPrivateKeyBlobType)))
            {
                try
                {
                    byte[] keyBlob = key.Export(format);
                    var key2 = rsa.ImportKeyPair(keyBlob, format);
                    byte[] key2Blob = key2.Export(format);

                    CollectionAssertEx.AreEqual(keyBlob, key2Blob);
                    Debug.WriteLine("Format {0} supported.", format);
                    supportedFormats++;
                }
                catch (NotSupportedException)
                {
                    Debug.WriteLine("Format {0} NOT supported.", format);
                }
            }

            Assert.IsTrue(supportedFormats > 0, "No supported formats.");
        }

        [TestMethod]
        public void PublicKeyRoundTrip()
        {
            var rsa = WinRTCrypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            var key = rsa.CreateKeyPair(512);

            int supportedFormats = 0;
            foreach (CryptographicPublicKeyBlobType format in Enum.GetValues(typeof(CryptographicPublicKeyBlobType)))
            {
                try
                {
                    byte[] keyBlob = key.ExportPublicKey(format);
                    var key2 = rsa.ImportPublicKey(keyBlob, format);
                    byte[] key2Blob = key2.ExportPublicKey(format);

                    CollectionAssertEx.AreEqual(keyBlob, key2Blob);
                    Debug.WriteLine("Format {0} supported.", format);
                    supportedFormats++;
                }
                catch (NotSupportedException)
                {
                    Debug.WriteLine("Format {0} NOT supported.", format);
                }
            }

            Assert.IsTrue(supportedFormats > 0, "No supported formats.");
        }
    }
}
