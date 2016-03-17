// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

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

#if !SILVERLIGHT
        /// <summary>
        /// The key formatter for BCrypt RSA private keys.
        /// </summary>
        internal static readonly KeyFormatter BCryptRsaPrivateKey = new BCryptRsaKeyFormatter(CryptographicPrivateKeyBlobType.BCryptPrivateKey);

        /// <summary>
        /// The key formatter for BCrypt RSA full private keys.
        /// </summary>
        internal static readonly KeyFormatter BCryptRsaFullPrivateKey = new BCryptRsaKeyFormatter(CryptographicPrivateKeyBlobType.BCryptFullPrivateKey);

        /// <summary>
        /// The key formatter for BCrypt RSA public keys.
        /// </summary>
        internal static readonly KeyFormatter BCryptRsaPublicKey = new BCryptRsaKeyFormatter(CryptographicPublicKeyBlobType.BCryptPublicKey);
#endif

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
                    return Pkcs1;
                case CryptographicPrivateKeyBlobType.Capi1PrivateKey:
                    return Capi;
#if !SILVERLIGHT
                case CryptographicPrivateKeyBlobType.BCryptPrivateKey:
                    return BCryptRsaPrivateKey;
                case CryptographicPrivateKeyBlobType.BCryptFullPrivateKey:
                    return BCryptRsaFullPrivateKey;
#endif
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
                    return Pkcs1;
                case CryptographicPublicKeyBlobType.Capi1PublicKey:
                    return Capi;
#if !SILVERLIGHT
                case CryptographicPublicKeyBlobType.BCryptPublicKey:
                    return BCryptRsaPublicKey;
#endif
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
            return TrimLeadingZeros(parameters);
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
                int keyLength = Math.Max(parameters.Modulus.Length, parameters.D?.Length ?? 0);
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
            if (buffer == null)
            {
                return null;
            }

            if (buffer.Length > 0 && buffer[0] == 0)
            {
                byte[] trimmed = new byte[buffer.Length - 1];
                Buffer.BlockCopy(buffer, 1, trimmed, 0, trimmed.Length);
                return trimmed;
            }

            return buffer;
        }

        /// <summary>
        /// Trim all leading zeros from an <see cref="RSAParameters"/> struct.
        /// </summary>
        /// <param name="parameters">The struct from which to remove parameters.</param>
        /// <returns>The trimmed version of the struct.</returns>
        protected static RSAParameters TrimLeadingZeros(RSAParameters parameters)
        {
            return new RSAParameters
            {
                Modulus = TrimLeadingZero(parameters.Modulus),
                Exponent = TrimLeadingZero(parameters.Exponent),
                D = TrimLeadingZero(parameters.D),
                P = TrimLeadingZero(parameters.P),
                DP = TrimLeadingZero(parameters.DP),
                Q = TrimLeadingZero(parameters.Q),
                DQ = TrimLeadingZero(parameters.DQ),
                InverseQ = TrimLeadingZero(parameters.InverseQ),
            };
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
            Requires.Range(desiredLength > 0, "desiredLength");

            if (buffer == null)
            {
                return null;
            }

            byte[] result = buffer;
            if (buffer.Length > desiredLength)
            {
                result = TrimLeadingZero(buffer);
            }
            else if (buffer.Length < desiredLength)
            {
                result = PrependLeadingZero(buffer, alwaysPrependZero: true);
            }

            try
            {
                VerifyFormat(result.Length == desiredLength);
            }
            catch (FormatException ex)
            {
                throw new NotSupportedException(ex.Message, ex);
            }

            return result;
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

            if ((buffer[0] & 0x80) == 0x80 || alwaysPrependZero)
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
        /// Returns a copy of the specified buffer where the copy has its byte order reversed.
        /// </summary>
        /// <param name="data">The buffer to copy and reverse.</param>
        /// <returns>The new buffer with the contents of the original buffer reversed.</returns>
        protected static byte[] CopyAndReverse(byte[] data)
        {
            byte[] reversed = new byte[data.Length];
            Array.Copy(data, 0, reversed, 0, data.Length);
            Array.Reverse(reversed);
            return reversed;
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
