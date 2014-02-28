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
    public class SymmetricKeyAlgorithmProviderTests
    {
        private readonly byte[] keyMaterial = new byte[16] { 0x2, 0x5, 0x11, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, };

        [TestMethod]
        public void BlockLength()
        {
            ISymmetricKeyAlgorithmProvider provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
            Assert.IsNotNull(provider);
            Assert.AreEqual(16, provider.BlockLength);
        }

        [TestMethod]
        public void CreateSymmetricKey_InvalidInputs()
        {
            var provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
            ExceptionAssert.Throws<ArgumentNullException>(
                () => provider.CreateSymmetricKey(null));
            ExceptionAssert.Throws<ArgumentException>(
                () => provider.CreateSymmetricKey(new byte[0]));
            ExceptionAssert.Throws<ArgumentException>(
                () => provider.CreateSymmetricKey(new byte[4]));
        }

        [TestMethod]
        public void CreateSymmetricKey()
        {
            var provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
            ICryptographicKey key = provider.CreateSymmetricKey(this.keyMaterial);
            Assert.IsNotNull(key);
        }

        [TestMethod]
        public void CreateSymmetricKey_Export()
        {
            var provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
            ICryptographicKey key = provider.CreateSymmetricKey(this.keyMaterial);
            ExceptionAssert.Throws<NotSupportedException>(
                () => key.Export());
        }

        [TestMethod]
        public void CreateSymmetricKey_ExportPublicKey()
        {
            var provider = WinRTCrypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
            ICryptographicKey key = provider.CreateSymmetricKey(this.keyMaterial);
            ExceptionAssert.Throws<NotSupportedException>(
                () => key.ExportPublicKey());
        }
    }
}
