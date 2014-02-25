namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
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
            var rsa = Crypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            Assert.AreEqual(AsymmetricAlgorithm.RsaOaepSha1, rsa.Algorithm);
        }

        [TestMethod]
        public void CreateKeyPair_InvalidInputs()
        {
            var rsa = Crypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            ExceptionAssert.Throws<ArgumentOutOfRangeException>(() =>
                rsa.CreateKeyPair(-1));
            ExceptionAssert.Throws<ArgumentOutOfRangeException>(() =>
                rsa.CreateKeyPair(0));
        }

        [TestMethod]
        public void CreateKeyPair()
        {
            var rsa = Crypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            var key = rsa.CreateKeyPair(512);
            Assert.IsNotNull(key);
            Assert.AreEqual(512, key.KeySize);
        }

        [TestMethod]
        public void ImportKeyPair_Null()
        {
            var rsa = Crypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            ExceptionAssert.Throws<ArgumentNullException>(
                () => rsa.ImportKeyPair(null));
        }

        [TestMethod]
        public void ImportPublicKey_Null()
        {
            var rsa = Crypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);
            ExceptionAssert.Throws<ArgumentNullException>(
                () => rsa.ImportPublicKey(null));
        }

        [TestMethod]
        public void KeyPairRoundTrip()
        {
            var rsa = Crypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);

            var key = rsa.CreateKeyPair(512);
            byte[] keyBlob = key.Export();

            var key2 = rsa.ImportKeyPair(keyBlob);
            byte[] key2Blob = key2.Export();

            CollectionAssertEx.AreEqual(keyBlob, key2Blob);
        }

        [TestMethod]
        public void PublicKeyRoundTrip()
        {
            var rsa = Crypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithm.RsaOaepSha1);

            var key = rsa.CreateKeyPair(512);
            byte[] keyBlob = key.ExportPublicKey();

            var key2 = rsa.ImportPublicKey(keyBlob);
            byte[] key2Blob = key2.ExportPublicKey();

            CollectionAssertEx.AreEqual(keyBlob, key2Blob);
        }
    }
}
