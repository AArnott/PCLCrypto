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
    public abstract class CryptoStreamTests
    {
        private readonly byte[] data = new byte[] { 0x1, 0x2, };

        [TestMethod]
        public void DisposeAlsoDisposesTargetStream()
        {
            var transform = new MockCryptoTransform(5);
            var targetStream = new MemoryStream();
            this.CreateCryptoStream(targetStream, transform, CryptoStreamMode.Write).Dispose();
            ExceptionAssert.Throws<ObjectDisposedException>(() => { long dummy = targetStream.Length; });
        }

        [TestMethod]
        public void DisposeAlsoDoesNotDisposeTransform()
        {
            var hasher = new MockCryptoTransform(5);
            this.CreateCryptoStream(Stream.Null, hasher, CryptoStreamMode.Write).Dispose();
            Assert.IsFalse(hasher.IsDisposed);
        }

        [TestMethod]
        public void CryptoStreamWithEmptyFinalBlockViaWrite()
        {
            var transform = new MockCryptoTransform(5);
            var target = new MemoryStream();
            using (var stream = this.CreateCryptoStream(target, transform, CryptoStreamMode.Write))
            {
                stream.Write(Encoding.UTF8.GetBytes("ABCD"), 1, 3);
                stream.Write(Encoding.UTF8.GetBytes("EFGHI"), 0, 4);
                stream.Write(Encoding.UTF8.GetBytes("JKLMNOPQ"), 0, 8);
                this.FlushFinalBlock(stream);
                Assert.AreEqual("-BCDEF-GHJKL-MNOPQ_Z", Encoding.UTF8.GetString(target.ToArray()));
            }
        }

        [TestMethod]
        public void CryptoStreamWithNonEmptyFinalBlockViaWrite()
        {
            var transform = new MockCryptoTransform(5);
            var target = new MemoryStream();
            using (var stream = this.CreateCryptoStream(target, transform, CryptoStreamMode.Write))
            {
                stream.Write(Encoding.UTF8.GetBytes("ABCD"), 1, 3);
                stream.Write(Encoding.UTF8.GetBytes("EFGHI"), 0, 4);
                stream.Write(Encoding.UTF8.GetBytes("JKLMNOPQRS"), 0, 10);
                this.FlushFinalBlock(stream);
                Assert.AreEqual("-BCDEF-GHJKL-MNOPQ_RSZ", Encoding.UTF8.GetString(target.ToArray()));
            }
        }

        [TestMethod]
        public void CryptoStreamWithEmptyFinalBlockViaRead()
        {
            var transform = new MockCryptoTransform(5);
            var target = new MemoryStream(Encoding.UTF8.GetBytes("BCDEFGHJKLMNOPQ"));
            using (var stream = this.CreateCryptoStream(target, transform, CryptoStreamMode.Read))
            {
                byte[] buffer = new byte[100];
                Assert.AreEqual(4, stream.Read(buffer, 0, 4));
                Assert.AreEqual("-BCD", Encoding.UTF8.GetString(buffer, 0, 4));
                Assert.AreEqual(5, stream.Read(buffer, 4, 5));
                Assert.AreEqual("EF-GH", Encoding.UTF8.GetString(buffer, 4, 5));
                Assert.AreEqual(11, stream.Read(buffer, 9, 11));
                Assert.AreEqual("JKL-MNOPQ_Z", Encoding.UTF8.GetString(buffer, 9, 11));

                string expected = "-BCDEF-GHJKL-MNOPQ_Z";
                Assert.AreEqual(expected, Encoding.UTF8.GetString(buffer, 0, expected.Length));
            }
        }

        [TestMethod]
        public void CryptoStreamWithNonEmptyFinalBlockViaRead()
        {
            var transform = new MockCryptoTransform(5);
            var target = new MemoryStream(Encoding.UTF8.GetBytes("BCDEFGHJKLMNOPQRS"));
            using (var stream = this.CreateCryptoStream(target, transform, CryptoStreamMode.Read))
            {
                byte[] buffer = new byte[100];
                Assert.AreEqual(4, stream.Read(buffer, 0, 4));
                Assert.AreEqual("-BCD", Encoding.UTF8.GetString(buffer, 0, 4));
                Assert.AreEqual(5, stream.Read(buffer, 4, 5));
                Assert.AreEqual("EF-GH", Encoding.UTF8.GetString(buffer, 4, 5));
                Assert.AreEqual(13, stream.Read(buffer, 9, 13));
                Assert.AreEqual("JKL-MNOPQ_RSZ", Encoding.UTF8.GetString(buffer, 9, 13));

                string expected = "-BCDEF-GHJKL-MNOPQ_RSZ";
                Assert.AreEqual(expected, Encoding.UTF8.GetString(buffer, 0, expected.Length));
            }
        }

        protected abstract Stream CreateCryptoStream(Stream target, ICryptoTransform transform, CryptoStreamMode mode);

        protected abstract void FlushFinalBlock(Stream stream);

        private class MockCryptoTransform : ICryptoTransform
        {
            internal MockCryptoTransform(int inputBlockSize)
            {
                this.InputBlockSize = inputBlockSize;
                this.OutputBlockSize = inputBlockSize + 1;
            }

            public bool CanReuseTransform
            {
                get { throw new NotImplementedException(); }
            }

            public bool CanTransformMultipleBlocks
            {
                get { return false; }
            }

            public int InputBlockSize { get; private set; }

            public int OutputBlockSize { get; private set; }

            internal bool IsDisposed { get; private set; }

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                outputBuffer[outputOffset] = (byte)'-';
                Array.Copy(inputBuffer, inputOffset, outputBuffer, outputOffset + 1, inputCount);
                return this.OutputBlockSize;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                byte[] result = new byte[inputCount + 2];
                result[0] = (byte)'_';
                result[result.Length - 1] = (byte)'Z';
                Array.Copy(inputBuffer, inputOffset, result, 1, inputCount);
                return result;
            }

            public void Dispose()
            {
                this.IsDisposed = true;
            }
        }
    }
}
