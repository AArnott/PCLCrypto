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
    public class RandomNumberGeneratorDesktopTests
    {
        [TestMethod]
        public void GetNonZeroBytes()
        {
            var rng = NetFxCrypto.RandomNumberGenerator as System.Security.Cryptography.RandomNumberGenerator;
            Assert.IsNotNull(rng);
            byte[] buffer = new byte[15];
            rng.GetNonZeroBytes(buffer);
            Assert.IsTrue(buffer.All(b => b != 0));
        }

        [TestMethod]
        public void GetNonZeroBytes_Null()
        {
            var rng = NetFxCrypto.RandomNumberGenerator as System.Security.Cryptography.RandomNumberGenerator;
            Assert.IsNotNull(rng);
            ExceptionAssert.Throws<ArgumentNullException>(() => rng.GetNonZeroBytes(null));
        }
    }
}
