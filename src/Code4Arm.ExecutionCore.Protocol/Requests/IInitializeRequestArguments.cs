﻿// IInitializeRequestArguments.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using Newtonsoft.Json;

namespace Code4Arm.ExecutionCore.Protocol.Requests;

public interface IInitializeRequestArguments
{
    /// <summary>
    /// The ID of the(frontend) client using this adapter.
    /// </summary>
    [Optional]
    [JsonProperty("clientID")]
    string? ClientId { get; set; }

    /// <summary>
    /// The human readable name of the(frontend) client using this adapter.
    /// </summary>
    [Optional]
    string? ClientName { get; set; }

    /// <summary>
    /// The ID of the debug adapter.
    /// </summary>
    [JsonProperty("adapterID")]
    string AdapterId { get; set; }

    /// <summary>
    /// The ISO-639 locale of the(frontend) client using this adapter, e.g.en-US or de-CH.
    /// </summary>
    [Optional]
    string? Locale { get; set; }

    /// <summary>
    /// If true all line numbers are 1-based(default).
    /// </summary>
    [Optional]
    bool LinesStartAt1 { get; set; }

    /// <summary>
    /// If true all column numbers are 1-based(default).
    /// </summary>
    [Optional]
    bool ColumnsStartAt1 { get; set; }

    /// <summary>
    /// Determines in what format paths are specified.The default is 'path', which is the native format.
    /// Values: 'path', 'uri', etc.
    /// </summary>
    [Optional]
    PathFormat? PathFormat { get; set; }

    /// <summary>
    /// Client supports the optional type attribute for variables.
    /// </summary>
    [Optional]
    bool SupportsVariableType { get; set; }

    /// <summary>
    /// Client supports the paging of variables.
    /// </summary>
    [Optional]
    bool SupportsVariablePaging { get; set; }

    /// <summary>
    /// Client supports the runInTerminal request.
    /// </summary>
    [Optional]
    bool SupportsRunInTerminalRequest { get; set; }

    /// <summary>
    /// Client supports memory references.
    /// </summary>
    [Optional]
    bool SupportsMemoryReferences { get; set; }

    /// <summary>
    /// Client supports progress reporting.
    /// </summary>
    [Optional]
    bool SupportsProgressReporting { get; set; }

    /// <summary>
    /// Client supports the invalidated event.
    /// </summary>
    [Optional]
    bool SupportsInvalidatedEvent { get; set; }
}
