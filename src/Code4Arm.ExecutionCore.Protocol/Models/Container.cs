// Container.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using System.Collections.Immutable;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;

namespace Code4Arm.ExecutionCore.Protocol.Models;

public static class Container
{
    [return: NotNullIfNotNull("items")]
    public static Container<T>? From<T>(IEnumerable<T>? items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };

    [return: NotNullIfNotNull("items")]
    public static Container<T>? From<T>(params T[] items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };

    [return: NotNullIfNotNull("items")]
    public static Container<T>? From<T>(List<T>? items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };

    [return: NotNullIfNotNull("items")]
    public static Container<T>? From<T>(in ImmutableArray<T>? items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };

    [return: NotNullIfNotNull("items")]
    public static Container<T>? From<T>(ImmutableList<T>? items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };
}

public class Container<T> : ContainerBase<T>
{
    public Container() : this(Enumerable.Empty<T>())
    {
    }

    public Container(IEnumerable<T> items) : base(items)
    {
    }

    public Container(params T[] items) : base(items)
    {
    }

    [return: NotNullIfNotNull("items")]
    public static Container<T>? From(IEnumerable<T>? items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };

    [return: NotNullIfNotNull("items")]
    public static implicit operator Container<T>?(T[] items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };

    [return: NotNullIfNotNull("items")]
    public static Container<T>? From(params T[] items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };

    [return: NotNullIfNotNull("items")]
    public static implicit operator Container<T>?(Collection<T>? items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };

    [return: NotNullIfNotNull("items")]
    public static Container<T>? From(Collection<T>? items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };

    [return: NotNullIfNotNull("items")]
    public static implicit operator Container<T>?(List<T>? items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };

    [return: NotNullIfNotNull("items")]
    public static Container<T>? From(List<T>? items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };

    [return: NotNullIfNotNull("items")]
    public static implicit operator Container<T>?(in ImmutableArray<T>? items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };

    [return: NotNullIfNotNull("items")]
    public static Container<T>? From(in ImmutableArray<T>? items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };

    [return: NotNullIfNotNull("items")]
    public static implicit operator Container<T>?(ImmutableList<T>? items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };

    [return: NotNullIfNotNull("items")]
    public static Container<T>? From(ImmutableList<T>? items) => items switch
    {
        not null => new Container<T>(items),
        _ => null
    };
}
