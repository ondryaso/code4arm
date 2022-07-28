// Container.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// 
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// Copyright (c) .NET Foundation and Contributors
// All Rights Reserved
// 
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Available under the MIT License.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
// to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of
// the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
