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
                () => NetFxCrypto.RandomNumberGenerator.GetBytes(null));
        }

        [TestMethod]
        public void GetBytes_Empty()
        {
            var buffer = new byte[0];
            NetFxCrypto.RandomNumberGenerator.GetBytes(buffer);
        }

        [TestMethod]
        public void GetBytes()
        {
            var buffer1 = new byte[4];
            NetFxCrypto.RandomNumberGenerator.GetBytes(buffer1);

            var buffer2 = new byte[4];
            NetFxCrypto.RandomNumberGenerator.GetBytes(buffer2);

            // Verify that the two randomly filled buffers are not equal.
            Assert.IsTrue(BitConverter.ToInt32(buffer1, 0) != BitConverter.ToInt32(buffer2, 0));
        }

#if !WinRT && !PCL && !WINDOWS_UWP
        [TestMethod]
        public void DesktopBaseClass()
        {
            Assert.IsTrue(NetFxCrypto.RandomNumberGenerator is System.Security.Cryptography.RandomNumberGenerator);
        }
#endif
    }
}
