namespace PCLCrypto.Formatters
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    internal class CapiKeyFormatter : KeyFormatter
    {
        protected override RSAParameters ReadCore(Stream stream)
        {
            byte[] keyBlob = new byte[stream.Length];
            stream.Read(keyBlob, 0, keyBlob.Length);
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportCspBlob(keyBlob);
            return rsa.ExportParameters(!rsa.PublicOnly);
        }

        protected override void WriteCore(Stream stream, RSAParameters parameters)
        {
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(parameters);
            byte[] keyBlob = rsa.ExportCspBlob(!rsa.PublicOnly);
            stream.Write(keyBlob, 0, keyBlob.Length);
        }
    }
}
