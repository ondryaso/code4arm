// Module.cs
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
using Newtonsoft.Json;

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// A Module object represents a row in the modules view.
/// Two attributes are mandatory: an id identifies a module in the modules view and is used in a ModuleEvent for
/// identifying a module for adding, updating or deleting.
/// The name is used to minimally render the module in the UI.
/// Additional attributes can be added to the module.They will show up in the module View if they have a corresponding
/// ColumnDescriptor.
/// To avoid an unnecessary proliferation of additional attributes with similar semantics but different names
/// we recommend to re-use attributes from the ‘recommended’ list below first, and only introduce new attributes if nothing
/// appropriate could be found.
/// </summary>
public record Module
{
    /// <summary>
    /// Unique identifier for the module.
    /// </summary>
    public NumberString Id { get; init; }

    /// <summary>
    /// A name of the module.
    /// </summary>
    public string Name { get; init; }

    /// <summary>
    /// optional but recommended attributes.
    /// always try to use these first before introducing additional attributes.
    /// Logical full path to the module. The exact definition is implementation defined, but usually this would be a full path
    /// to the on-disk file for the module.
    /// </summary>
    [Optional]
    public string? Path { get; init; }

    /// <summary>
    /// True if the module is optimized.
    /// </summary>
    [Optional]
    public bool IsOptimized { get; init; }

    /// <summary>
    /// True if the module is considered 'user code' by a debugger that supports 'Just My Code'.
    /// </summary>
    [Optional]
    public bool IsUserCode { get; init; }

    /// <summary>
    /// Version of Module.
    /// </summary>
    [Optional]
    public string? Version { get; init; }

    /// <summary>
    /// User understandable description of if symbols were found for the module (ex: 'Symbols Loaded', 'Symbols not found',
    /// etc.
    /// </summary>
    [Optional]
    public string? SymbolStatus { get; init; }

    /// <summary>
    /// Logical full path to the symbol file. The exact definition is implementation defined.
    /// </summary>
    [Optional]
    public string? SymbolFilePath { get; init; }

    /// <summary>
    /// Module created or modified.
    /// </summary>
    [Optional]
    public string? DateTimeStamp { get; init; }

    /// <summary>
    /// Address range covered by this module.
    /// </summary>
    [Optional]
    public string? AddressRange { get; init; }

    /// <summary>
    /// Allows additional data to be displayed
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, object> ExtensionData { get; init; } = new();
}
