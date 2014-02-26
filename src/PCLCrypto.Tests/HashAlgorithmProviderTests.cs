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
    public class HashAlgorithmProviderTests
    {
        [TestMethod]
        public void OpenAlgorithm()
        {
            IHashAlgorithmProvider provider = Crypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
            Assert.IsNotNull(provider);
        }

        [TestMethod]
        public void Algorithm()
        {
            var provider = Crypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
            Assert.AreEqual(HashAlgorithm.Sha1, provider.Algorithm);

            provider = Crypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256);
            Assert.AreEqual(HashAlgorithm.Sha256, provider.Algorithm);
        }
    }
}
