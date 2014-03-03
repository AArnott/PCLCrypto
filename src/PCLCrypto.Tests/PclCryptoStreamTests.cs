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
#pragma warning disable 0436
    public class PclCryptoStreamTests : CryptoStreamTests
#pragma warning restore 0436
    {
        [TestMethod]
        public void Ctor_InvalidArgs()
        {
            // NetFx version throws NullReferenceException.
            ExceptionAssert.Throws<ArgumentNullException>(
                () => this.CreateCryptoStream(null, new MockCryptoTransform(5), CryptoStreamMode.Write));
            ExceptionAssert.Throws<ArgumentNullException>(
                () => this.CreateCryptoStream(Stream.Null, null, CryptoStreamMode.Write));
        }

        [TestMethod]
        public void Write_NullBuffer()
        {
            using (var stream = this.CreateCryptoStream(Stream.Null, new MockCryptoTransform(5), CryptoStreamMode.Write))
            {
                ExceptionAssert.Throws<ArgumentNullException>(() => stream.Write(null, 0, 0));
            }
        }

        [TestMethod]
        public void Read_NullBuffer()
        {
            using (var stream = this.CreateCryptoStream(new MemoryStream(), new MockCryptoTransform(5), CryptoStreamMode.Read))
            {
                ExceptionAssert.Throws<ArgumentNullException>(() => stream.Read(null, 0, 0));
            }
        }

        [TestMethod]
        public void WriteTo_InvalidInputs()
        {
            ExceptionAssert.Throws<ArgumentNullException>(
                () => CryptoStream.WriteTo(null, new MockCryptoTransform(5)));
            ExceptionAssert.Throws<ArgumentException>(
                () => CryptoStream.WriteTo(Stream.Null));
            ExceptionAssert.Throws<ArgumentException>(
                () => CryptoStream.WriteTo(Stream.Null, null));
        }

        [TestMethod]
        public void ReadFrom_InvalidInputs()
        {
            ExceptionAssert.Throws<ArgumentNullException>(
                () => CryptoStream.ReadFrom(null, new MockCryptoTransform(5)));
            ExceptionAssert.Throws<ArgumentException>(
                () => CryptoStream.ReadFrom(Stream.Null));
            ExceptionAssert.Throws<ArgumentException>(
                () => CryptoStream.ReadFrom(Stream.Null, null));
        }

        [TestMethod]
        public void WriteTo()
        {
            var t1 = new MockCryptoTransform(6);
            var t2 = new MockCryptoTransform(9);
            var ms = new MemoryStream();
            using (var cryptoStream = CryptoStream.WriteTo(ms, t1, t2))
            {
                cryptoStream.Write(Encoding.UTF8.GetBytes("abcdefghijkl"), 0, 12);
            }

            Assert.AreEqual("--abcdef-g_hijkl_ZZ", Encoding.UTF8.GetString(ms.ToArray()));
        }

        [TestMethod]
        public void ReadFrom()
        {
            var t1 = new MockCryptoTransform(6);
            var t2 = new MockCryptoTransform(9);
            var ms = new MemoryStream(Encoding.UTF8.GetBytes("abcdefghijkl"));
            using (var cryptoStream = CryptoStream.ReadFrom(ms, t1, t2))
            {
                var buffer = new byte[100];
                int bytesRead = cryptoStream.Read(buffer, 0, 100);
                Assert.AreEqual("--abcdef-g_hijkl_ZZ", Encoding.UTF8.GetString(buffer, 0, bytesRead));
            }
        }

        protected override Stream CreateCryptoStream(Stream target, ICryptoTransform transform, CryptoStreamMode mode)
        {
            return new CryptoStream(target, transform, mode);
        }

        protected override void FlushFinalBlock(Stream stream)
        {
            ((CryptoStream)stream).FlushFinalBlock();
        }
    }
}
