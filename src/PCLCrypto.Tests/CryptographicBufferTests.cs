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
                () => WinRTCrypto.CryptographicBuffer.Compare(null, null));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicBuffer.Compare(new byte[0], null));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => WinRTCrypto.CryptographicBuffer.Compare(null, new byte[0]));
        }

        [TestMethod]
        public void Compare_EqualBufferLengths()
        {
            Assert.IsTrue(WinRTCrypto.CryptographicBuffer.Compare(new byte[2], new byte[2]));
            Assert.IsTrue(WinRTCrypto.CryptographicBuffer.Compare(new byte[] { 0x1, 0x2 }, new byte[] { 0x1, 0x2 }));
            Assert.IsFalse(WinRTCrypto.CryptographicBuffer.Compare(new byte[] { 0x1, 0x3 }, new byte[] { 0x1, 0x2 }));
            Assert.IsFalse(WinRTCrypto.CryptographicBuffer.Compare(new byte[] { 0x3, 0x2 }, new byte[] { 0x1, 0x2 }));
        }

        [TestMethod]
        public void Compare_UnequalBufferLengths()
        {
            Assert.IsFalse(WinRTCrypto.CryptographicBuffer.Compare(new byte[] { 0x1 }, new byte[] { 0x1, 0x2 }));
            Assert.IsFalse(WinRTCrypto.CryptographicBuffer.Compare(new byte[] { 0x1, 0x2 }, new byte[] { 0x1 }));
        }

        [TestMethod]
        public void GenerateRandom_ZeroLength()
        {
            byte[] buffer = WinRTCrypto.CryptographicBuffer.GenerateRandom(0);
            Assert.AreEqual(0, buffer.Length);
        }

        [TestMethod]
        public void EncodeToHexString_InvalidInputs()
        {
            ExceptionAssert.Throws<ArgumentNullException>(() => WinRTCrypto.CryptographicBuffer.EncodeToHexString(null));
        }

        [TestMethod]
        public void EncodeToHexString_EmptyBuffer()
        {
            Assert.AreEqual(string.Empty, WinRTCrypto.CryptographicBuffer.EncodeToHexString(new byte[0]));
        }

        [TestMethod]
        public void EncodeToHexString()
        {
            Assert.AreEqual("00010faefff0", WinRTCrypto.CryptographicBuffer.EncodeToHexString(new byte[] { 0x00, 0x1, 0xf, 0xae, 0xff, 0xf0 }));
        }

        [TestMethod]
        public void DecodeFromHexString_InvalidInputs()
        {
            ExceptionAssert.Throws<ArgumentNullException>(() => WinRTCrypto.CryptographicBuffer.DecodeFromHexString(null));
            ExceptionAssert.Throws<ArgumentException>(() => WinRTCrypto.CryptographicBuffer.DecodeFromHexString("123")); // odd length
        }

        [TestMethod]
        public void DecodeFromHexString_EmptyString()
        {
            CollectionAssertEx.AreEqual(new byte[0], WinRTCrypto.CryptographicBuffer.DecodeFromHexString(string.Empty));
        }

        [TestMethod]
        public void DecodeFromHexString()
        {
            CollectionAssertEx.AreEqual(new byte[] { 0x00, 0x1, 0xf, 0xae, 0xff, 0xf0 }, WinRTCrypto.CryptographicBuffer.DecodeFromHexString("00010faefff0"));
        }

        [TestMethod]
        public void GenerateRandom()
        {
            byte[] buffer1 = WinRTCrypto.CryptographicBuffer.GenerateRandom(15);
            Assert.AreEqual(15, buffer1.Length);

            byte[] buffer2 = WinRTCrypto.CryptographicBuffer.GenerateRandom(15);
            Assert.AreEqual(15, buffer2.Length);

            CollectionAssertEx.AreNotEqual(buffer1, buffer2);
        }

        [TestMethod]
        public void GenerateRandomNumber()
        {
            uint random1 = WinRTCrypto.CryptographicBuffer.GenerateRandomNumber();
            uint random2 = WinRTCrypto.CryptographicBuffer.GenerateRandomNumber();
            uint random3 = WinRTCrypto.CryptographicBuffer.GenerateRandomNumber();

            // The odds of all three being equal should be *very* small.
            Assert.IsTrue(random1 != random2 || random2 != random3);
        }
    }
}
