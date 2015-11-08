//-----------------------------------------------------------------------
// <copyright file="KeyFormatter.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto.Formatters
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Validation;

    /// <summary>
    /// A base class for encoding and decoding RSA keys in various formats.
    /// </summary>
    internal abstract class KeyFormatter
    {
        /// <summary>
        /// The PKCS1 key formatter.
        /// </summary>
        internal static readonly KeyFormatter Pkcs1 = new Pkcs1KeyFormatter();

        /// <summary>
        /// The PKCS1 key formatter that prepends zeros to certain RSA parameters.
        /// </summary>
        internal static readonly KeyFormatter Pkcs1PrependZeros = new Pkcs1KeyFormatter(prependLeadingZeroOnCertainElements: true);

        /// <summary>
        /// The PKCS8 key formatter.
        /// </summary>
        internal static readonly KeyFormatter Pkcs8 = new Pkcs8KeyFormatter();

        /// <summary>
        /// The X509 subject public key information formatter.
        /// </summary>
        internal static readonly KeyFormatter X509SubjectPublicKeyInfo = new X509SubjectPublicKeyInfoFormatter();

        /// <summary>
        /// The CAPI key formatter.
        /// </summary>
        internal static readonly KeyFormatter Capi = new CapiKeyFormatter();

        /// <summary>
        /// The PKCS1 object identifier
        /// </summary>
        protected static readonly byte[] Pkcs1ObjectIdentifier = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01 };

        /// <summary>
        /// The RSA encryption object identifier
        /// </summary>
        protected static readonly byte[] RsaEncryptionObjectIdentifier = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };

        /// <summary>
        /// Gets the formatter to use for a given blob type.
        /// </summary>
        /// <param name="blobType">Type of the key blob.</param>
        /// <returns>An instance of <see cref="KeyFormatter"/></returns>
        internal static KeyFormatter GetFormatter(CryptographicPrivateKeyBlobType blobType)
        {
            switch (blobType)
            {
                case CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo:
                    return Pkcs8;
                case CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey:
                    return Pkcs1PrependZeros;
                case CryptographicPrivateKeyBlobType.Capi1PrivateKey:
                    return Capi;
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets the formatter to use for a given blob type.
        /// </summary>
        /// <param name="blobType">Type of the key blob.</param>
        /// <returns>An instance of <see cref="KeyFormatter"/></returns>
        internal static KeyFormatter GetFormatter(CryptographicPublicKeyBlobType blobType)
        {
            switch (blobType)
            {
                case CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo:
                    return X509SubjectPublicKeyInfo;
                case CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey:
                    return Pkcs1PrependZeros;
                case CryptographicPublicKeyBlobType.Capi1PublicKey:
                    return Capi;
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Writes a key to the specified stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="parameters">The parameters.</param>
        internal void Write(Stream stream, RSAParameters parameters)
        {
            this.Write(stream, parameters, HasPrivateKey(parameters));
        }

        /// <summary>
        /// Writes a key to the specified stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="parameters">The parameters.</param>
        /// <param name="includePrivateKey">if set to <c>true</c> the private key will be written as well; otherwise just the public key will be written.</param>
        internal void Write(Stream stream, RSAParameters parameters, bool includePrivateKey)
        {
            Requires.NotNull(stream, "stream");
            Requires.Argument(HasPrivateKey(parameters) || !includePrivateKey, "parameters", "No private key data included.");

            if (!includePrivateKey)
            {
                parameters = PublicKeyFilter(parameters);
            }

            this.WriteCore(stream, parameters);
        }

        /// <summary>
        /// Writes a key to a buffer.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns>The buffer with the serialized key.</returns>
        internal byte[] Write(RSAParameters parameters)
        {
            return this.Write(parameters, HasPrivateKey(parameters));
        }

        /// <summary>
        /// Writes a key to a buffer.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="includePrivateKey">if set to <c>true</c> the private key will be written as well; otherwise just the public key will be written.</param>
        /// <returns>The buffer with the serialized key.</returns>
        internal byte[] Write(RSAParameters parameters, bool includePrivateKey)
        {
            var ms = new MemoryStream();
            this.Write(ms, parameters, includePrivateKey);
            return ms.ToArray();
        }

        /// <summary>
        /// Reads a key from the specified stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <returns>The RSA key parameters.</returns>
        internal RSAParameters Read(Stream stream)
        {
            var parameters = this.ReadCore(stream);

#if DESKTOP
            if (!CapiKeyFormatter.IsCapiCompatible(parameters))
            {
                // CAPI is faster than RSAManaged, so try to reformat the key
                // such that CAPI can represent it, if possible.
                // But some RSA keys (especially those generated by iOS devices)
                // have their P component with more sig figs than their Q component,
                // in which case CAPI just can't handle it.
                // Only change the RSA parameters if we expect it will be useful,
                // since changing them on iOS actually makes the app crash.
                var trimmedParameters = NegotiateSizes(parameters);
                if (CapiKeyFormatter.IsCapiCompatible(trimmedParameters))
                {
                    return trimmedParameters;
                }
            }
#endif

            return parameters;
        }

        /// <summary>
        /// Reads a key from the specified buffer.
        /// </summary>
        /// <param name="keyBlob">The buffer containing the key data.</param>
        /// <returns>The RSA key parameters.</returns>
        internal RSAParameters Read(byte[] keyBlob)
        {
            var ms = new MemoryStream(keyBlob);
            return this.Read(ms);
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

        /// <summary>
        /// Tries to add/remove leading zeros as necessary in an attempt to make the parameters CAPI compatible.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns>The modified set of parameters.</returns>
        /// <remarks>
        /// The original parameters and their buffers are not modified.
        /// </remarks>
        protected internal static RSAParameters NegotiateSizes(RSAParameters parameters)
        {
            if (HasPrivateKey(parameters))
            {
                if (CapiKeyFormatter.IsCapiCompatible(parameters))
                {
                    // Don't change a thing. Everything is perfect.
                    return parameters;
                }

                parameters.Modulus = TrimLeadingZero(parameters.Modulus);
                parameters.D = TrimLeadingZero(parameters.D);
                int keyLength = Math.Max(parameters.Modulus.Length, parameters.D.Length);
                parameters.Modulus = TrimOrPadZeroToLength(parameters.Modulus, keyLength);
                parameters.D = TrimOrPadZeroToLength(parameters.D, keyLength);

                int halfKeyLength = (keyLength + 1) / 2;
                parameters.P = TrimOrPadZeroToLength(parameters.P, halfKeyLength);
                parameters.Q = TrimOrPadZeroToLength(parameters.Q, halfKeyLength);
                parameters.DP = TrimOrPadZeroToLength(parameters.DP, halfKeyLength);
                parameters.DQ = TrimOrPadZeroToLength(parameters.DQ, halfKeyLength);
                parameters.InverseQ = TrimOrPadZeroToLength(parameters.InverseQ, halfKeyLength);
            }
            else
            {
                parameters.Modulus = TrimLeadingZero(parameters.Modulus);
            }

            parameters.Exponent = TrimLeadingZero(parameters.Exponent);
            return parameters;
        }

        /// <summary>
        /// Determines whether a set of RSA parameters includes a private key.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns><c>true</c> if a private key is included; <c>false</c> otherwise.</returns>
        protected internal static bool HasPrivateKey(RSAParameters parameters)
        {
            return parameters.P != null;
        }

#if !WinRT && (!SILVERLIGHT || WINDOWS_PHONE) // we just want SL5 excluded

        /// <summary>
        /// Converts the PCLCrypto <see cref="RSAParameters"/> struct to the type
        /// offered by the .NET Framework.
        /// </summary>
        /// <param name="value">The PCLCrypto parameters.</param>
        /// <returns>The .NET Framework parameters.</returns>
        protected internal static System.Security.Cryptography.RSAParameters ToPlatformParameters(RSAParameters value)
        {
            return new System.Security.Cryptography.RSAParameters
            {
                D = value.D,
                Q = value.Q,
                P = value.P,
                DP = value.DP,
                DQ = value.DQ,
                Exponent = value.Exponent,
                InverseQ = value.InverseQ,
                Modulus = value.Modulus,
            };
        }

        /// <summary>
        /// Converts the .NET Framework <see cref="RSAParameters"/> struct to the type
        /// offered by the PCLCrypto library.
        /// </summary>
        /// <param name="value">The .NET Framework parameters.</param>
        /// <returns>The PCLCrypto parameters.</returns>
        protected internal static RSAParameters ToPCLParameters(System.Security.Cryptography.RSAParameters value)
        {
            return new RSAParameters
            {
                D = value.D,
                Q = value.Q,
                P = value.P,
                DP = value.DP,
                DQ = value.DQ,
                Exponent = value.Exponent,
                InverseQ = value.InverseQ,
                Modulus = value.Modulus,
            };
        }

#endif

        /// <summary>
        /// Checks whether two buffers have equal contents.
        /// </summary>
        /// <param name="buffer1">The first buffer.</param>
        /// <param name="buffer2">The second buffer.</param>
        /// <returns><c>true</c> if the buffers contain equal contents.</returns>
        protected static bool BufferEqual(byte[] buffer1, byte[] buffer2)
        {
            Requires.NotNull(buffer1, "buffer1");
            Requires.NotNull(buffer2, "buffer2");

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
            Requires.NotNull(buffer, "buffer");

            if (buffer.Length > 0 && buffer[0] == 0)
            {
                byte[] trimmed = new byte[buffer.Length - 1];
                Buffer.BlockCopy(buffer, 1, trimmed, 0, trimmed.Length);
                return trimmed;
            }

            return buffer;
        }

        /// <summary>
        /// Trims up to one leading byte from the start of a buffer if that byte is a 0x00
        /// without modifying the original buffer.
        /// </summary>
        /// <param name="buffer">The buffer.</param>
        /// <param name="desiredLength">The length to try to trim or pad to match.</param>
        /// <returns>
        /// A buffer without a leading zero. It may be the same buffer as was provided if no leading zero was found.
        /// </returns>
        protected static byte[] TrimOrPadZeroToLength(byte[] buffer, int desiredLength)
        {
            Requires.NotNull(buffer, "buffer");
            Requires.Range(desiredLength > 0, "desiredLength");

            if (buffer.Length > desiredLength)
            {
                return TrimLeadingZero(buffer);
            }
            else if (buffer.Length < desiredLength)
            {
                return PrependLeadingZero(buffer);
            }
            else
            {
                return buffer;
            }
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
            Requires.NotNull(buffer, "buffer");

            if (buffer[0] != 0 || alwaysPrependZero)
            {
                byte[] modifiedBuffer = new byte[buffer.Length + 1];
                Buffer.BlockCopy(buffer, 0, modifiedBuffer, 1, buffer.Length);
                return modifiedBuffer;
            }

            return buffer;
        }

        /// <summary>
        /// Throws an exception if a condition does not evaluate to true.
        /// </summary>
        /// <param name="condition">if set to <c>false</c> an exception will be thrown.</param>
        /// <param name="message">An optional message describing the failure.</param>
        protected static void VerifyFormat(bool condition, string message = null)
        {
            if (!condition)
            {
                FailFormat(message);
            }
        }

        /// <summary>
        /// Throws an exception. For use during key deserialization.
        /// </summary>
        /// <param name="message">An optional message describing the failure.</param>
        /// <returns>Nothing. This method always throws.</returns>
        protected static Exception FailFormat(string message = null)
        {
            throw new FormatException(message ?? "Unexpected format or unsupported key.");
        }

        /// <summary>
        /// Reads a key from the specified stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <returns>The RSA Parameters of the key.</returns>
        protected abstract RSAParameters ReadCore(Stream stream);

        /// <summary>
        /// Writes a key to the specified stream.
        /// </summary>
        /// <param name="stream">The stream.</param>
        /// <param name="parameters">The RSA parameters of the key.</param>
        protected abstract void WriteCore(Stream stream, RSAParameters parameters);
    }
}
