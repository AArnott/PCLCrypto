namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Platform = System.Security.Cryptography;

    internal class RandomNumberGenerator : IRandomNumberGenerator
    {
        public void GetBytes(byte[] buffer)
        {
            var random = Platform.RandomNumberGenerator.Create();
            random.GetBytes(buffer);
        }
    }
}
