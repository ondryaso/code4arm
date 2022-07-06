// SteppingGranularity.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Code4Arm.ExecutionCore.Protocol.Models;

[JsonConverter(typeof(StringEnumConverter))]
public enum SteppingGranularity
{
    Statement,
    Line,
    Instruction
}
