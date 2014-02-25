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
            var keyPair = rsa.CreateKeyPair(512);
            Assert.IsNotNull(keyPair);
        }
    }
}
