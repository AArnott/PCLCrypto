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
    public class DeriveBytesTests
    {
        private const string Password1 = "Password";
        private static readonly byte[] Salt1 = new byte[] { 0x1, 0x2, 0x4, 0x5, 0x3, 0x6, 0x7, 0x8 };
        private static readonly byte[] Salt2 = new byte[] { 0x1, 0x3, 0x2, 0x5, 0x3, 0x6, 0x7, 0x8 };

        [TestMethod]
        public void GetBytes()
        {
            byte[] keyFromPassword = NetFxCrypto.DeriveBytes.GetBytes(Password1, Salt1, 5, 10);
            byte[] keyFromBytes = NetFxCrypto.DeriveBytes.GetBytes(Encoding.UTF8.GetBytes(Password1), Salt1, 5, 10);
            CollectionAssertEx.AreEqual(keyFromPassword, keyFromBytes);

            byte[] keyWithOtherSalt = NetFxCrypto.DeriveBytes.GetBytes(Password1, Salt2, 5, 10);
            CollectionAssertEx.AreNotEqual(keyFromPassword, keyWithOtherSalt);
        }

        [TestMethod]
        public void GetBytes_NullBytes()
        {
            ExceptionAssert.Throws<ArgumentNullException>(() => NetFxCrypto.DeriveBytes.GetBytes((byte[])null, Salt1, 5, 10));
        }

        [TestMethod]
        public void GetBytes_NullPassword()
        {
            ExceptionAssert.Throws<ArgumentNullException>(() => NetFxCrypto.DeriveBytes.GetBytes((string)null, Salt1, 5, 10));
        }

        [TestMethod]
        public void GetBytes_Password_NullSalt()
        {
            ExceptionAssert.Throws<ArgumentNullException>(() => NetFxCrypto.DeriveBytes.GetBytes(Password1, null, 5, 10));
        }

        [TestMethod]
        public void GetBytes_Bytes_NullSalt()
        {
            ExceptionAssert.Throws<ArgumentNullException>(() => NetFxCrypto.DeriveBytes.GetBytes(Encoding.UTF8.GetBytes(Password1), null, 5, 10));
        }
    }
}
