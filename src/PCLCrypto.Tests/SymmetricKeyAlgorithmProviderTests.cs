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
        [TestMethod]
        public void OpenAlgorithm()
        {
            ISymmetricKeyAlgorithmProvider provider = Crypto.SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithm.AesCbcPkcs7);
            Assert.IsNotNull(provider);
        }
    }
}
