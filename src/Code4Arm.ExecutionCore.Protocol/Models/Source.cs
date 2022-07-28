// Source.cs
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

using Code4Arm.ExecutionCore.Protocol.Serialization;
using Code4Arm.ExecutionCore.Protocol.StringEnum;
using Newtonsoft.Json.Linq;

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// A Source is a descriptor for source code.
/// It is returned from the debug adapter as part of a StackFrame and it is used by clients when specifying breakpoints.
/// </summary>
public record Source
{
    /// <summary>
    /// The short name of the source. Every source returned from the debug adapter has a name. When sending a source to the
    /// debug adapter this name is optional.
    /// </summary>
    [Optional]
    public string? Name { get; init; }

    /// <summary>
    /// The path of the source to be shown in the UI. It is only used to locate and load the content of the source if no
    /// sourceReference is specified (or its value is 0).
    /// </summary>
    [Optional]
    public string? Path { get; init; }

    /// <summary>
    /// If sourceReference > 0 the contents of the source must be retrieved through the SourceRequest (even if a path is
    /// specified). A sourceReference is only valid for a session, so it
    /// must not be used to persist a source.
    /// </summary>
    [Optional]
    public long? SourceReference { get; init; }

    /// <summary>
    /// An optional hint for how to present the source in the UI. A value of 'deemphasize' can be used to indicate that the
    /// source is not available or that it is skipped on stepping.
    /// </summary>
    [Optional]
    public SourcePresentationHint? PresentationHint { get; init; }

    /// <summary>
    /// The (optional) origin of this source: possible values 'internal module', 'inlined content from source map', etc.
    /// </summary>
    [Optional]
    public string? Origin { get; init; }

    /// <summary>
    /// An optional list of sources that are related to this source. These may be the source that generated this source.
    /// </summary>
    [Optional]
    public Container<Source>? Sources { get; init; }

    /// <summary>
    /// Optional data that a debug adapter might want to loop through the client. The client should leave the data intact and
    /// persist it across sessions. The client should not interpret the data.
    /// </summary>
    [Optional]
    public JToken? AdapterData { get; init; }

    /// <summary>
    /// The checksums associated with this file.
    /// </summary>
    [Optional]
    public Container<Checksum>? Checksums { get; init; }
}

public class SourcePresentationHint : StringEnum<SourcePresentationHint>
{
    public static readonly SourcePresentationHint Normal = Create("normal");
    public static readonly SourcePresentationHint Emphasize = Create("emphasize");
    public static readonly SourcePresentationHint Deemphasize = Create("deemphasize");
}
