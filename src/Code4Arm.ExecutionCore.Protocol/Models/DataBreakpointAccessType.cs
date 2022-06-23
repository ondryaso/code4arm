// DataBreakpointAccessType.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// This enumeration defines all possible access types for data breakpoints.
/// </summary>
[JsonConverter(typeof(StringEnumConverter))]
public enum DataBreakpointAccessType
{
    Read,
    Write,
    ReadWrite
}
