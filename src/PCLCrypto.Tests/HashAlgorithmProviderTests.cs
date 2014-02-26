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
        private readonly byte[] data = new byte[] { 0x1, 0x2, };

        private readonly string dataHash = @"DKYj4oVfLHXIQq0wL+gg5BtNGX0=";

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

        [TestMethod]
        public void HashData()
        {
            var hasher = Crypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
            var hash = hasher.HashData(this.data);
            Assert.IsNotNull(hash);
            Assert.AreEqual(this.dataHash, Convert.ToBase64String(hash));
        }

        [TestMethod]
        public void HashData_InvalidInputs()
        {
            var hasher = Crypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256);
            ExceptionAssert.Throws<ArgumentNullException>(
                () => hasher.HashData(null));
        }
    }
}
