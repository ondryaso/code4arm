// RequestNames.cs
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

namespace Code4Arm.ExecutionCore.Protocol.Requests;

public static class RequestNames
{
    public const string Initialize = "initialize";
    public const string ConfigurationDone = "configurationDone";
    public const string Launch = "launch";
    public const string Attach = "attach";
    public const string Restart = "restart";
    public const string Disconnect = "disconnect";
    public const string Terminate = "terminate";
    public const string BreakpointLocations = "breakpointLocations";
    public const string SetBreakpoints = "setBreakpoints";
    public const string SetFunctionBreakpoints = "setFunctionBreakpoints";
    public const string SetExceptionBreakpoints = "setExceptionBreakpoints";
    public const string DataBreakpointInfo = "dataBreakpointInfo";
    public const string SetDataBreakpoints = "setDataBreakpoints";
    public const string SetInstructionBreakpoints = "setInstructionBreakpoints";
    public const string Continue = "continue";
    public const string Next = "next";
    public const string StepIn = "stepIn";
    public const string StepOut = "stepOut";
    public const string StepBack = "stepBack";
    public const string ReverseContinue = "reverseContinue";
    public const string RestartFrame = "restartFrame";
    public const string Goto = "goto";
    public const string Pause = "pause";
    public const string StackTrace = "stackTrace";
    public const string Scopes = "scopes";
    public const string Variables = "variables";
    public const string SetVariable = "setVariable";
    public const string Source = "source";

    public const string Threads = "threads";
    public const string TerminateThreads = "terminateThreads";
    public const string Modules = "modules";
    public const string LoadedSources = "loadedSources";
    public const string Evaluate = "evaluate";
    public const string SetExpression = "setExpression";
    public const string StepInTargets = "stepInTargets";
    public const string GotoTargets = "gotoTargets";
    public const string Completions = "completions";
    public const string ExceptionInfo = "exceptionInfo";
    public const string ReadMemory = "readMemory";
    public const string Disassemble = "disassemble";
    public const string RunInTerminal = "runInTerminal";
    public const string Cancel = "cancel";
}
