namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    public interface IRandomNumberGenerator
    {
        void GetBytes(byte[] buffer);
    }
}
