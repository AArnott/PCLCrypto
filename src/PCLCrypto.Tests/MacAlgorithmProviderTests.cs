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
    public class MacAlgorithmProviderTests
    {
        private readonly byte[] keyMaterial = new byte[] { 0x1, 0x23, 0x15 };

        private readonly byte[] data = Encoding.UTF8.GetBytes("hello");

        private readonly string macBase64 = "WJJtHvbUeB7r1ORCnZjxXxK78Nk=";

        [TestMethod]
        public void OpenAlgorithm()
        {
            var algorithm = Crypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.AesCmac);
            Assert.IsNotNull(algorithm);
        }

        [TestMethod]
        public void Algorithm()
        {
            var algorithm = Crypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.AesCmac);
            Assert.AreEqual(MacAlgorithm.AesCmac, algorithm.Algorithm);

            algorithm = Crypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
            Assert.AreEqual(MacAlgorithm.HmacSha1, algorithm.Algorithm);
        }

        [TestMethod]
        public void MacLength()
        {
            var algorithm = Crypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
            Assert.AreEqual(20, algorithm.MacLength);

            algorithm = Crypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha256);
            Assert.AreEqual(256 / 8, algorithm.MacLength);
        }

        [TestMethod]
        public void CreateHash_InvalidInputs()
        {
            var algorithm = Crypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
            ExceptionAssert.Throws<ArgumentNullException>(
                () => algorithm.CreateHash(null));
            ExceptionAssert.Throws<ArgumentException>(
                () => algorithm.CreateHash(new byte[0]));
        }

        [TestMethod]
        public void CreateHash()
        {
            var algorithm = Crypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
            ICryptographicHash hasher = algorithm.CreateHash(this.keyMaterial);
            Assert.IsNotNull(hasher);
            hasher.Append(this.data);
            byte[] mac = hasher.GetValueAndReset();
            Assert.AreEqual(this.macBase64, Convert.ToBase64String(mac));
        }

        [TestMethod]
        public void CreateKey_InvalidInputs()
        {
            var algorithm = Crypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
            ExceptionAssert.Throws<ArgumentNullException>(
                () => algorithm.CreateKey(null));
        }

        [TestMethod]
        public void CreateKey()
        {
            var algorithm = Crypto.MacAlgorithmProvider.OpenAlgorithm(MacAlgorithm.HmacSha1);
            ICryptographicKey key = algorithm.CreateKey(this.keyMaterial);
            Assert.IsNotNull(key);
            byte[] mac = Crypto.CryptographicEngine.Sign(key, this.data);
            Assert.AreEqual(this.macBase64, Convert.ToBase64String(mac));
        }
    }
}
