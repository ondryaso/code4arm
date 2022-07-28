// EventNames.cs
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
