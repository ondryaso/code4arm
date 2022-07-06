// EventNames.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

namespace Code4Arm.ExecutionCore.Protocol.Events;

public static class EventNames
{
    public const string Initialized = "initialized";
    public const string Stopped = "stopped";
    public const string Invalidated = "invalidated";
    public const string Continued = "continued";
    public const string Exited = "exited";
    public const string Terminated = "terminated";
    public const string Thread = "thread";
    public const string Output = "output";
    public const string Breakpoint = "breakpoint";
    public const string Module = "module";
    public const string Memory = "memory";
    public const string LoadedSource = "loadedSource";
    public const string Process = "process";
    public const string Capabilities = "capabilities";
    public const string ProgressStart = "progressStart";
    public const string ProgressUpdate = "progressUpdate";
    public const string ProgressEnd = "progressEnd";
}
