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
        public void IncompatibleStreamDirection()
        {
            ExceptionAssert.Throws<ArgumentException>(
                () => this.CreateCryptoStream(new ErraticReaderStream(Stream.Null), new MockCryptoTransform(5), CryptoStreamMode.Write));
            ExceptionAssert.Throws<ArgumentException>(
                () => this.CreateCryptoStream(new MockWriteOnlyStream(), new MockCryptoTransform(5), CryptoStreamMode.Read));
        }

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
        public void CannotReadFromWriteStream()
        {
            var transform = new MockCryptoTransform(5);
            var target = new MemoryStream();
            using (var stream = this.CreateCryptoStream(target, transform, CryptoStreamMode.Write))
            {
                byte[] buffer = new byte[1];
                ExceptionAssert.Throws<NotSupportedException>(
                    () => stream.Read(buffer, 0, 1));
            }
        }

        [TestMethod]
        public void CannotWriteToReadStream()
        {
            var transform = new MockCryptoTransform(5);
            var target = new MemoryStream();
            using (var stream = this.CreateCryptoStream(target, transform, CryptoStreamMode.Read))
            {
                byte[] buffer = new byte[1];
                ExceptionAssert.Throws<NotSupportedException>(
                    () => stream.Write(buffer, 0, 1));
            }
        }

        [TestMethod]
        public void Write_InvalidInputs()
        {
            using (var stream = this.CreateCryptoStream(Stream.Null, new MockCryptoTransform(5), CryptoStreamMode.Write))
            {
                // .NET Framework version throws NRE for Read(null). We test it in PCL derived test class.
                ////ExceptionAssert.Throws<ArgumentNullException>(() => stream.Write(null, 0, 0));
                ExceptionAssert.Throws<ArgumentOutOfRangeException>(() => stream.Write(new byte[1], -1, 1));
                ExceptionAssert.Throws<ArgumentOutOfRangeException>(() => stream.Write(new byte[1], 0, -1));
            }
        }

        [TestMethod]
        public void Read_InvalidInputs()
        {
            using (var stream = this.CreateCryptoStream(new MemoryStream(), new MockCryptoTransform(5), CryptoStreamMode.Read))
            {
                // .NET Framework version throws NRE for Read(null). We test it in PCL derived test class.
                ////ExceptionAssert.Throws<ArgumentNullException>(() => stream.Read(null, 0, 0));
                ExceptionAssert.Throws<ArgumentOutOfRangeException>(() => stream.Read(new byte[1], -1, 1));
                ExceptionAssert.Throws<ArgumentOutOfRangeException>(() => stream.Read(new byte[1], 0, -1));
            }
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
                Assert.AreEqual(11, stream.Read(buffer, 9, 12));
                Assert.AreEqual("JKL-MNOPQ_Z", Encoding.UTF8.GetString(buffer, 9, 11));
                Assert.AreEqual(0, stream.Read(buffer, 0, 10)); // EOF

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
                Assert.AreEqual(13, stream.Read(buffer, 9, 14));
                Assert.AreEqual("JKL-MNOPQ_RSZ", Encoding.UTF8.GetString(buffer, 9, 13));
                Assert.AreEqual(0, stream.Read(buffer, 0, 10)); // EOF

                string expected = "-BCDEF-GHJKL-MNOPQ_RSZ";
                Assert.AreEqual(expected, Encoding.UTF8.GetString(buffer, 0, expected.Length));
            }
        }

        [TestMethod]
        public void CanTransformMultipleBlocksViaWrite()
        {
            var transform = new MockCryptoTransform(5, canTransformMultipleBlocks: true);
            var target = new MemoryStream();
            using (var stream = this.CreateCryptoStream(target, transform, CryptoStreamMode.Write))
            {
                stream.Write(Encoding.UTF8.GetBytes("abcdefghij"), 0, 10);
                stream.Write(Encoding.UTF8.GetBytes("klm"), 0, 3);
                stream.Write(Encoding.UTF8.GetBytes("nop"), 0, 3);
                stream.Write(Encoding.UTF8.GetBytes("qrstuvwxyz"), 0, 10);
                this.FlushFinalBlock(stream);
                Assert.AreEqual("-abcdefghij-klmno-pqrst-uvwxy_zZ", Encoding.UTF8.GetString(target.ToArray()));
            }

            transform = new MockCryptoTransform(5, canTransformMultipleBlocks: true);
            target = new MemoryStream();
            using (var stream = this.CreateCryptoStream(target, transform, CryptoStreamMode.Write))
            {
                stream.Write(Encoding.UTF8.GetBytes("abc"), 0, 3);
                stream.Write(Encoding.UTF8.GetBytes("defghijklmnop"), 0, 13);
                this.FlushFinalBlock(stream);
                Assert.AreEqual("-abcde-fghijklmno_pZ", Encoding.UTF8.GetString(target.ToArray()));
            }

            transform = new MockCryptoTransform(5, canTransformMultipleBlocks: true);
            target = new MemoryStream();
            using (var stream = this.CreateCryptoStream(target, transform, CryptoStreamMode.Write))
            {
                stream.Write(Encoding.UTF8.GetBytes("abcdefghijk"), 0, 11);
                this.FlushFinalBlock(stream);
                Assert.AreEqual("-abcdefghij_kZ", Encoding.UTF8.GetString(target.ToArray()));
            }
        }

        protected abstract Stream CreateCryptoStream(Stream target, ICryptoTransform transform, CryptoStreamMode mode);

        protected abstract void FlushFinalBlock(Stream stream);

        protected class MockCryptoTransform : ICryptoTransform
        {
            internal MockCryptoTransform(int inputBlockSize, bool canTransformMultipleBlocks = false)
            {
                this.InputBlockSize = inputBlockSize;
                this.OutputBlockSize = inputBlockSize + 1;
                this.CanTransformMultipleBlocks = canTransformMultipleBlocks;
            }

            public bool CanReuseTransform
            {
                get { throw new NotImplementedException(); }
            }

            public bool CanTransformMultipleBlocks { get; private set; }

            public int InputBlockSize { get; private set; }

            public int OutputBlockSize { get; private set; }

            internal bool IsDisposed { get; private set; }

            internal bool FinalBlockTransformed { get; private set; }

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                if (this.CanTransformMultipleBlocks)
                {
                    Assert.IsTrue(inputCount % this.InputBlockSize == 0);
                }
                else
                {
                    Assert.IsTrue(inputCount == this.InputBlockSize);
                }

                outputBuffer[outputOffset] = (byte)'-';
                Array.Copy(inputBuffer, inputOffset, outputBuffer, outputOffset + 1, inputCount);
                return inputCount + 1;
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
        /// Well, a Stream.Read method may return n number of bytes 0 &lt; n &lt;= desiredCount
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

        private class MockWriteOnlyStream : Stream
        {
            public override bool CanRead
            {
                get { return false; }
            }

            public override bool CanSeek
            {
                get { return false; }
            }

            public override bool CanWrite
            {
                get { return true; }
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
                throw new NotImplementedException();
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
