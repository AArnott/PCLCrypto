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
    public class RandomNumberGeneratorTests
    {
        [TestMethod]
        public void GetBytes_Null()
        {
            ExceptionAssert.Throws<ArgumentNullException>(
                () => Crypto.RandomNumberGenerator.GetBytes(null));
        }

        [TestMethod]
        public void GetBytes_Empty()
        {
            var buffer = new byte[0];
            Crypto.RandomNumberGenerator.GetBytes(buffer);
        }

        [TestMethod]
        public void GetBytes()
        {
            var buffer1 = new byte[4];
            Crypto.RandomNumberGenerator.GetBytes(buffer1);

            var buffer2 = new byte[4];
            Crypto.RandomNumberGenerator.GetBytes(buffer2);

            // Verify that the two randomly filled buffers are not equal.
            Assert.IsTrue(BitConverter.ToInt32(buffer1, 0) != BitConverter.ToInt32(buffer2, 0));
        }

#if !WinRT && !PCL
        [TestMethod]
        public void DesktopBaseClass()
        {
            Assert.IsTrue(Crypto.RandomNumberGenerator is System.Security.Cryptography.RandomNumberGenerator);
        }
#endif
    }
}
