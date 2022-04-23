// ProgressToken.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using System.Diagnostics;

namespace Code4Arm.ExecutionCore.Protocol.Models;

[DebuggerDisplay("{" + nameof(DebuggerDisplay) + ",nq}")]
public record ProgressToken : IEquatable<long>, IEquatable<string>
{
    private long? _long;
    private string? _string;

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

    private string DebuggerDisplay => IsString ? String : IsLong ? Long.ToString() : "";

    public ProgressToken(Guid value)
    {
        _string = value.ToString();
        _long = null;
    }

    public ProgressToken(long value)
    {
        _long = value;
        _string = null;
    }

    public ProgressToken(string value)
    {
        _long = null;
        _string = value;
    }

    public bool Equals(long other) => IsLong && (Long == other);
    public bool Equals(string other) => IsString && (String == other);

    public static implicit operator ProgressToken(long value) => new(value);

    public static implicit operator ProgressToken(string value) => new(value);
    public static implicit operator ProgressToken(Guid value) => new(value);

    /// <inheritdoc/>
    public override string ToString() => DebuggerDisplay;
}
