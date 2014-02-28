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
    public class CryptographicBufferTests
    {
        [TestMethod]
        public void Compare_NullInputs()
        {
            ExceptionAssert.Throws<ArgumentNullException>(
                () => Crypto.CryptographicBuffer.Compare(null, null));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => Crypto.CryptographicBuffer.Compare(new byte[0], null));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => Crypto.CryptographicBuffer.Compare(null, new byte[0]));
        }

        [TestMethod]
        public void Compare_EqualBufferLengths()
        {
            Assert.IsTrue(Crypto.CryptographicBuffer.Compare(new byte[2], new byte[2]));
            Assert.IsTrue(Crypto.CryptographicBuffer.Compare(new byte[] { 0x1, 0x2 }, new byte[] { 0x1, 0x2 }));
            Assert.IsFalse(Crypto.CryptographicBuffer.Compare(new byte[] { 0x1, 0x3 }, new byte[] { 0x1, 0x2 }));
            Assert.IsFalse(Crypto.CryptographicBuffer.Compare(new byte[] { 0x3, 0x2 }, new byte[] { 0x1, 0x2 }));
        }

        [TestMethod]
        public void Compare_UnequalBufferLengths()
        {
            Assert.IsFalse(Crypto.CryptographicBuffer.Compare(new byte[] { 0x1 }, new byte[] { 0x1, 0x2 }));
            Assert.IsFalse(Crypto.CryptographicBuffer.Compare(new byte[] { 0x1, 0x2 }, new byte[] { 0x1 }));
        }

        [TestMethod]
        public void GenerateRandom_ZeroLength()
        {
            byte[] buffer = Crypto.CryptographicBuffer.GenerateRandom(0);
            Assert.AreEqual(0, buffer.Length);
        }

        [TestMethod]
        public void GenerateRandom()
        {
            byte[] buffer1 = Crypto.CryptographicBuffer.GenerateRandom(15);
            Assert.AreEqual(15, buffer1.Length);

            byte[] buffer2 = Crypto.CryptographicBuffer.GenerateRandom(15);
            Assert.AreEqual(15, buffer2.Length);

            CollectionAssertEx.AreNotEqual(buffer1, buffer2);
        }

        [TestMethod]
        public void GenerateRandomNumber()
        {
            uint random1 = Crypto.CryptographicBuffer.GenerateRandomNumber();
            uint random2 = Crypto.CryptographicBuffer.GenerateRandomNumber();
            uint random3 = Crypto.CryptographicBuffer.GenerateRandomNumber();

            // The odds of all three being equal should be *very* small.
            Assert.IsTrue(random1 != random2 || random2 != random3);
        }
    }
}
