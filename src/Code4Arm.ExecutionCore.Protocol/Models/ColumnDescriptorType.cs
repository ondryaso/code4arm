// ColumnDescriptorType.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.StringEnum;

namespace Code4Arm.ExecutionCore.Protocol.Models;

public class ColumnDescriptorType : StringEnum<ColumnDescriptorType>
{
    public static readonly ColumnDescriptorType String = Create("string");
    public static readonly ColumnDescriptorType Long = Create("long");
    public static readonly ColumnDescriptorType Bool = Create("boolean");
    public static readonly ColumnDescriptorType UnixTimestampUtc = Create("unixTimestampUTC");
}
