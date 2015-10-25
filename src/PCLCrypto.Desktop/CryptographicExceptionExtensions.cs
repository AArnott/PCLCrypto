// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// Extension methosd for the <see cref="CryptographicException"/> class.
    /// </summary>
    internal static class CryptographicExceptionExtensions
    {
#pragma warning disable SA1310 // Field names must not contain underscore
        private const int NTE_NOT_SUPPORTED = unchecked((int)0x80090029);
#pragma warning restore SA1310 // Field names must not contain underscore

        /// <summary>
        /// Checks whether the specified exception originates represents a "Not supported" error.
        /// </summary>
        /// <param name="exception">The exception to check.</param>
        /// <returns><c>true</c> if the exception is definitely a 'not supported' exception.</returns>
        internal static bool IsNotSupportedException(this CryptographicException exception)
        {
            if (exception != null)
            {
                try
                {
                    // Do a best effort to recognize a not supported exception.
                    var hresultField = typeof(CryptographicException).GetField("_HResult", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                    if (hresultField != null)
                    {
                        int hresult = (int)hresultField.GetValue(exception);
                        if (hresult == NTE_NOT_SUPPORTED)
                        {
                            return true;
                        }
                    }
                }
                catch
                {
                }
            }

            return false;
        }
    }
}
