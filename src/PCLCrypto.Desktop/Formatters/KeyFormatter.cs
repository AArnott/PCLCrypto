namespace PCLCrypto.Formatters
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using Validation;

    internal abstract class KeyFormatter
    {
        internal static readonly KeyFormatter Pkcs1 = new Pkcs1KeyFormatter();

        internal static readonly KeyFormatter Pkcs1PrependZeros = new Pkcs1KeyFormatter(prependLeadingZeroOnCertainElements: true);

        internal static readonly KeyFormatter Pkcs8 = new Pkcs8KeyFormatter();

        internal static readonly KeyFormatter X509SubjectPublicKeyInfo = new X509SubjectPublicKeyInfoFormatter();

        internal static readonly KeyFormatter Capi = new CapiKeyFormatter();

        protected static readonly byte[] Pkcs1ObjectIdentifier = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01 };

        protected static readonly byte[] RsaEncryptionObjectIdentifier = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

        internal KeyFormatter GetFormatter(CryptographicPrivateKeyBlobType blobType)
        {
            switch (blobType)
            {
                case CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo:
                    return Pkcs8;
                case CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey:
                    return Pkcs1;
                case CryptographicPrivateKeyBlobType.Capi1PrivateKey:
                    return Capi;
                default:
                    throw new NotSupportedException();
            }
        }

        internal KeyFormatter GetFormatter(CryptographicPublicKeyBlobType blobType)
        {
            switch (blobType)
            {
                case CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo:
                    return X509SubjectPublicKeyInfo;
                case CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey:
                    return Pkcs1;
                case CryptographicPublicKeyBlobType.Capi1PublicKey:
                    return Capi;
                default:
                    throw new NotSupportedException();
            }
        }

        internal void Write(Stream stream, RSAParameters parameters)
        {
            Write(stream, parameters, HasPrivateKey(parameters));
        }

        internal void Write(Stream stream, RSAParameters parameters, bool includePrivateKey)
        {
            Requires.NotNull(stream, "stream");
            Requires.Argument(HasPrivateKey(parameters) || !includePrivateKey, "parameters", "No private key data included.");

            this.WriteCore(stream, includePrivateKey ? parameters : PublicKeyFilter(parameters));
        }

        internal byte[] Write(RSAParameters parameters)
        {
            return Write(parameters, HasPrivateKey(parameters));
        }

        internal byte[] Write(RSAParameters parameters, bool includePrivateKey)
        {
            var ms = new MemoryStream();
            this.Write(ms, parameters, includePrivateKey);
            return ms.ToArray();
        }

        internal RSAParameters Read(Stream stream)
        {
            return this.ReadCore(stream);
        }

        internal RSAParameters Read(byte[] keyBlob)
        {
            var ms = new MemoryStream(keyBlob);
            return this.Read(ms);
        }

        protected abstract RSAParameters ReadCore(Stream stream);

        protected abstract void WriteCore(Stream stream, RSAParameters parameters);

        protected static bool HasPrivateKey(RSAParameters parameters)
        {
            return parameters.P != null;
        }

        protected static bool BufferEqual(byte[] buffer1, byte[] buffer2)
        {
            if (buffer1.Length != buffer2.Length)
            {
                return false;
            }

            for (int i = 0; i < buffer1.Length; i++)
            {
                if (buffer1[i] != buffer2[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Trims up to one leading byte from the start of a buffer if that byte is a 0x00
        /// without modifying the original buffer.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <returns>A buffer without a leading zero. It may be the same buffer as was provided if no leading zero was found.</returns>
        protected static byte[] TrimLeadingZero(byte[] buffer)
        {
            if (buffer.Length > 0 && buffer[0] == 0)
            {
                byte[] trimmed = new byte[buffer.Length - 1];
                Buffer.BlockCopy(buffer, 1, trimmed, 0, trimmed.Length);
                return trimmed;
            }

            return buffer;
        }

        /// <summary>
        /// Returns a buffer with a 0x00 byte prepended if the buffer doesn't start with that byte.
        /// </summary>
        /// <param name="buffer">The buffer to prepend.</param>
        /// <param name="alwaysPrependZero">if set to <c>true</c> a new buffer with a zero prepended will always be returned, even if the given buffer already has a leading zero.</param>
        /// <returns>
        /// A buffer with the prepended zero.
        /// </returns>
        protected static byte[] PrependLeadingZero(byte[] buffer, bool alwaysPrependZero = false)
        {
            if (buffer[0] != 0 || alwaysPrependZero)
            {
                byte[] modifiedBuffer = new byte[buffer.Length + 1];
                Buffer.BlockCopy(buffer, 0, modifiedBuffer, 1, buffer.Length);
                return modifiedBuffer;
            }

            return buffer;
        }

        protected static void VerifyFormat(bool condition, string message = null)
        {
            if (!condition)
            {
                FailFormat(message);
            }
        }

        protected static Exception FailFormat(string message = null)
        {
            throw new FormatException(message ?? "Unexpected format or unsupported key.");
        }

        /// <summary>
        /// Returns an instance of <see cref="RSAParameters"/> that does not contain private key info.
        /// </summary>
        /// <param name="value">The RSA parameters which may include a private key.</param>
        /// <returns>An instance of <see cref="RSAParameters"/> that only includes public key information.</returns>
        protected internal static RSAParameters PublicKeyFilter(RSAParameters value)
        {
            return new RSAParameters
            {
                Modulus = value.Modulus,
                Exponent = value.Exponent,
            };
        }
    }
}
