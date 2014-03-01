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
    using Validation;

    [TestClass]
    public abstract class CryptoStreamTests
    {
        [TestMethod]
        public void Properties()
        {
            var stream = this.CreateCryptoStream(Stream.Null, new MockCryptoTransform(5), CryptoStreamMode.Write);
            Assert.IsTrue(stream.CanWrite);
            Assert.IsFalse(stream.CanRead);
            Assert.IsFalse(stream.CanSeek);
            Assert.IsFalse(stream.CanTimeout);
            ExceptionAssert.Throws<NotSupportedException>(() => { long dummy = stream.Length; });
            ExceptionAssert.Throws<NotSupportedException>(() => { long dummy = stream.Position; });
            ExceptionAssert.Throws<NotSupportedException>(() => { stream.Position = 0; });

            stream = this.CreateCryptoStream(Stream.Null, new MockCryptoTransform(5), CryptoStreamMode.Read);
            Assert.IsTrue(stream.CanRead);
            Assert.IsFalse(stream.CanWrite);
            Assert.IsFalse(stream.CanSeek);
            Assert.IsFalse(stream.CanTimeout);
            ExceptionAssert.Throws<NotSupportedException>(() => { long dummy = stream.Length; });
            ExceptionAssert.Throws<NotSupportedException>(() => { long dummy = stream.Position; });
            ExceptionAssert.Throws<NotSupportedException>(() => { stream.Position = 0; });
        }

        [TestMethod]
        public void DisposeAlsoDisposesTargetStream()
        {
            var transform = new MockCryptoTransform(5);
            var targetStream = new MemoryStream();
            this.CreateCryptoStream(targetStream, transform, CryptoStreamMode.Write).Dispose();
            ExceptionAssert.Throws<ObjectDisposedException>(() => { long dummy = targetStream.Length; });
        }

        [TestMethod]
        public void DisposeDoesNotDisposeTransform()
        {
            var hasher = new MockCryptoTransform(5);
            this.CreateCryptoStream(Stream.Null, hasher, CryptoStreamMode.Write).Dispose();
            Assert.IsFalse(hasher.IsDisposed);
        }

        [TestMethod]
        public void DisposeTransformsFinalBlock()
        {
            var hasher = new MockCryptoTransform(5);
            this.CreateCryptoStream(Stream.Null, hasher, CryptoStreamMode.Write).Dispose();
            Assert.IsTrue(hasher.FinalBlockTransformed);
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
            var target = new ErraticReaderStream(new MemoryStream(Encoding.UTF8.GetBytes("BCDEFGHJKLMNOPQ")));
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

        protected class MockCryptoTransform : ICryptoTransform
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

            internal bool FinalBlockTransformed { get; private set; }

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                outputBuffer[outputOffset] = (byte)'-';
                Array.Copy(inputBuffer, inputOffset, outputBuffer, outputOffset + 1, inputCount);
                return this.OutputBlockSize;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                Verify.Operation(!this.FinalBlockTransformed, "Final block already transformed.");

                this.FinalBlockTransformed = true;
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

        /// <summary>
        /// A readable stream that usually returns less than the number of bytes requested.
        /// </summary>
        /// <remarks>
        /// Why would we use such a stream?
        /// Well, a Stream.Read method may return n number of bytes 0 < n <= desiredCount
        /// Returning 0 bytes means the end of the stream has been reached.
        /// Returning less than the requested bytes could be due to reaching the end of the
        /// stream, but it may also be due to the underlying stream being a network stream
        /// and although the caller wants 500 bytes, only 300 are immediately available
        /// so those are returned. The caller can then turn around and ask for 200 more
        /// bytes, or any other number of bytes.
        /// We mock this up here to verify that stream readers are tolerant of this behavior.
        /// </remarks>
        protected class ErraticReaderStream : Stream
        {
            private readonly Stream underlyingStream;

            internal ErraticReaderStream(Stream underlyingStream)
            {
                Requires.NotNull(underlyingStream, "underlyingStream");
                this.underlyingStream = underlyingStream;
            }

            public override bool CanRead
            {
                get { return true; }
            }

            public override bool CanSeek
            {
                get { return false; }
            }

            public override bool CanWrite
            {
                get { return false; }
            }

            public override long Length
            {
                get { throw new NotImplementedException(); }
            }

            public override long Position
            {
                get { throw new NotImplementedException(); }
                set { throw new NotImplementedException(); }
            }

            public override void Flush()
            {
                throw new NotImplementedException();
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                // Always return one less byte than requested,
                // unless only 1 is requested, in which case return that many.
                // Returning 0 means end of stream.
                return this.underlyingStream.Read(buffer, offset, Math.Max(1, count - 1));
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotImplementedException();
            }

            public override void SetLength(long value)
            {
                throw new NotImplementedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotImplementedException();
            }
        }
    }
}
