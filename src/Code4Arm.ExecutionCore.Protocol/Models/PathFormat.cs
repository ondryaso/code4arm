// PathFormat.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.StringEnum;

namespace Code4Arm.ExecutionCore.Protocol.Models;

public class PathFormat : StringEnum<PathFormat>
{
    public static readonly PathFormat Path = Create("path");
    public static readonly PathFormat Uri = Create("uri");
}
