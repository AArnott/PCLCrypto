namespace PCLCrypto.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using Xunit;

    public class RandomNumberGeneratorDesktopTests
    {
        [Fact]
        public void GetNonZeroBytes()
        {
            var rng = NetFxCrypto.RandomNumberGenerator as System.Security.Cryptography.RandomNumberGenerator;
            Assert.NotNull(rng);
            byte[] buffer = new byte[15];
            rng.GetNonZeroBytes(buffer);
            Assert.True(buffer.All(b => b != 0));
        }

        [Fact]
        public void GetNonZeroBytes_Null()
        {
            var rng = NetFxCrypto.RandomNumberGenerator as System.Security.Cryptography.RandomNumberGenerator;
            Assert.NotNull(rng);
            Assert.Throws<ArgumentNullException>(() => rng.GetNonZeroBytes(null));
        }
    }
}
