// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

public static class CollectionAssertEx
{
    public static void AreEqual<T>(IEnumerable<T> expected, IEnumerable<T> actual)
    {
        Assert.False(expected == null ^ actual == null);
        if (expected == null)
        {
            return;
        }

        Assert.True(Enumerable.SequenceEqual(expected, actual));
    }

    public static void AreNotEqual<T>(IEnumerable<T> notExpected, IEnumerable<T> actual)
    {
        // Although they are not expected to be equal, we expect them to be non-null.
        Assert.NotNull(actual);
        Assert.NotNull(notExpected);

        Assert.False(Enumerable.SequenceEqual(notExpected, actual));
    }
}
