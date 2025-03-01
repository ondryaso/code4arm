// NumberString.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

namespace Code4Arm.ExecutionCore.Protocol.Models;

public struct NumberString
{
    private long? _long;
    private string? _string;

    public NumberString(long value)
    {
        _long = value;
        _string = null;
    }

    public NumberString(string value)
    {
        _long = null;
        _string = value;
    }

    public bool IsLong => _long.HasValue;

    public long Long
    {
        get => _long ?? 0;
        set
        {
            _string = null;
            _long = value;
        }
    }

    public bool IsString => _string != null;

    public string String
    {
        get => _string ?? string.Empty;
        set
        {
            _string = value;
            _long = null;
        }
    }

    public static implicit operator NumberString(long value) => new(value);

    public static implicit operator NumberString(string value) => new(value);
}
