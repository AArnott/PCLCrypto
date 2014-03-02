namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
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

        private readonly string dataHashTwice = @"7/byfLvaIq0efDyE+taJbZ8Y4JA=";

        [TestMethod]
        public void OpenAlgorithm()
        {
            IHashAlgorithmProvider provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
            Assert.IsNotNull(provider);
        }

        [TestMethod]
        public void Algorithm()
        {
            var provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
            Assert.AreEqual(HashAlgorithm.Sha1, provider.Algorithm);

            provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256);
            Assert.AreEqual(HashAlgorithm.Sha256, provider.Algorithm);
        }

        [TestMethod]
        public void HashData()
        {
            var hasher = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
            var hash = hasher.HashData(this.data);
            Assert.IsNotNull(hash);
            Assert.AreEqual(this.dataHash, Convert.ToBase64String(hash));
        }

        [TestMethod]
        public void HashData_InvalidInputs()
        {
            var hasher = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256);
            ExceptionAssert.Throws<ArgumentNullException>(
                () => hasher.HashData(null));
        }

        [TestMethod]
        public void HashLength()
        {
            var provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
            Assert.AreEqual(20, provider.HashLength);

            provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha256);
            Assert.AreEqual(256 / 8, provider.HashLength);
        }

        [TestMethod]
        public void CreateHash()
        {
            var provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
            var hasher = provider.CreateHash();
            Assert.IsNotNull(hasher);
        }

        [TestMethod]
        public void AppendAndGetValueAndReset()
        {
            var provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
            var hasher = provider.CreateHash();
            hasher.Append(this.data);
            byte[] hash = hasher.GetValueAndReset();
            Assert.AreEqual(this.dataHash, Convert.ToBase64String(hash));

            // Hash again to verify that everything was properly reset.
            hasher.Append(this.data);
            hash = hasher.GetValueAndReset();
            Assert.AreEqual(this.dataHash, Convert.ToBase64String(hash));
        }

        [TestMethod]
        public void AppendTwice()
        {
            var provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
            var hasher = provider.CreateHash();
            hasher.Append(this.data);
            hasher.Append(this.data);
            byte[] hash = hasher.GetValueAndReset();
            Assert.AreEqual(this.dataHashTwice, Convert.ToBase64String(hash));
        }

        [TestMethod]
        public void HashByCryptoStream()
        {
            var provider = WinRTCrypto.HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha1);
            var hasher = provider.CreateHash();
            using (var stream = new PCLCrypto.CryptoStream(Stream.Null, hasher, CryptoStreamMode.Write))
            {
                stream.Write(this.data, 0, this.data.Length);
            }

            Assert.AreEqual(this.dataHash, Convert.ToBase64String(hasher.GetValueAndReset()));
        }
    }
}
