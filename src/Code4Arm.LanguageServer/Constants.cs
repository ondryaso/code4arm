// Constants.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

using System.Collections.Immutable;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer;

public static class Constants
{
    /// Language ID for the Arm assembly language as defined in the client extension.
    public const string ArmUalLanguageId = "arm-ual";
    
    /// <summary>
    /// A document selector for our language ID.
    /// Using this lets the client extension control what files are considered Arm source files.
    /// </summary>
    public static readonly DocumentSelector ArmUalDocumentSelector = DocumentSelector.ForLanguage(ArmUalLanguageId);

    public const string ServiceSource = "code4arm";

    public const string ArmUalLanguageName = "Arm UAL";

    public const string ConfigurationSectionRoot = "code4arm.editor";

    public static readonly ImmutableList<string> SimulatedFunctions = ImmutableList<string>.Empty.AddRange(new []
    {
        "calloc", "malloc", "free", "realloc",
        "getchar", "putchar", "printf", "puts", "ungetc",
        "ReadInt32", "ReadUInt32", "ReadInt64", "ReadUInt64", "ReadFloat32", "ReadFloat64"
    });
}
