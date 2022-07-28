// Message.cs
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

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// A structured message object. Used to return errors from requests.
/// </summary>
public record Message
{
    /// <summary>
    /// Unique identifier for the message.
    /// </summary>
    public long Id { get; init; }

    /// <summary>
    /// A format string for the message. Embedded variables have the form '{name}'.
    /// If variable name starts with an underscore character, the variable does not contain user data (PII) and can be safely
    /// used for telemetry purposes.
    /// </summary>
    public string Format { get; init; }

    /// <summary>
    /// An object used as a dictionary for looking up the variables in the format string.
    /// </summary>
    [Optional]
    public IDictionary<string, string>? Variables { get; init; }

    /// <summary>
    /// If true send to telemetry.
    /// </summary>
    [Optional]
    public bool SendTelemetry { get; init; }

    /// <summary>
    /// If true show user.
    /// </summary>
    [Optional]
    public bool ShowUser { get; init; }

    /// <summary>
    /// An optional url where additional information about this message can be found.
    /// </summary>
    [Optional]
    public string? Url { get; init; }

    /// <summary>
    /// An optional label that is presented to the user as the UI for opening the url.
    /// </summary>
    [Optional]
    public string? UrlLabel { get; init; }
}
