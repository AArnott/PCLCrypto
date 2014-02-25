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
        public void OpenAlgorithm_Null()
        {
            ExceptionAssert.Throws<ArgumentNullException>(
                () => Crypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(null));
        }

        [TestMethod]
        public void OpenAlgorithm_EmptyString()
        {
            ExceptionAssert.Throws<ArgumentException>(
                () => Crypto.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(string.Empty));
        }
    }
}
