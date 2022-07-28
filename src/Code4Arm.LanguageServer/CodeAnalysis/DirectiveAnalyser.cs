// DirectiveAnalyser.cs
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
using Code4Arm.LanguageServer.Extensions;
using Code4Arm.LanguageServer.CodeAnalysis.Abstractions;
using Code4Arm.LanguageServer.CodeAnalysis.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.CodeAnalysis;

public class DirectiveAnalyser : IDirectiveAnalyser
{
    private Dictionary<string, DirectiveType> _directiveTypes = new()
    {
        {"type", DirectiveType.Type},
        {"arch", DirectiveType.Arch},
        {"arch_extension", DirectiveType.ArchExtension},
        {"code", DirectiveType.Code},
        {"cpu", DirectiveType.Cpu},
        {"text", DirectiveType.TextSection},
        {"data", DirectiveType.DataSection},
        {"bss", DirectiveType.BssSection},
        {"equ", DirectiveType.SetSymbol},
        {"set", DirectiveType.SetSymbol},
        {"equiv", DirectiveType.SetUndefinedSymbol},
        {"eqv", DirectiveType.SetUndefinedSymbol},
        {"error", DirectiveType.EmitError},
        {"err", DirectiveType.EmitError},
        {"warning", DirectiveType.EmitWarning},
        {"extern", DirectiveType.Extern},
        {"fill", DirectiveType.Fill},
        {"func", DirectiveType.Func},
        {"endfunc", DirectiveType.EndFunc},
        {"fnstart", DirectiveType.FnStart},
        {"fnend", DirectiveType.FnEnd},
        {"global", DirectiveType.Global},
        {"include", DirectiveType.Include},
        {"macro", DirectiveType.Macro},
        {"nop", DirectiveType.Nop},
        {"zero", DirectiveType.Zero},
        {"float16_format", DirectiveType.HalfFloatFormat},
        {"force_thumb", DirectiveType.ForceThumb},
        {"thumb", DirectiveType.Thumb},
        {"thumb_func", DirectiveType.ThumbFunc},
        {"syntax", DirectiveType.Syntax},
        {"size", DirectiveType.Size},
        {"float16", DirectiveType.HalfFloat},
        {"float", DirectiveType.SingleFloat},
        {"single", DirectiveType.SingleFloat},
        {"double", DirectiveType.DoubleFloat},
        {"octa", DirectiveType.Octa},
        {"quad", DirectiveType.Quad},
        {"word", DirectiveType.Word},
        {"long", DirectiveType.Word},
        {"int", DirectiveType.Word},
        {"short", DirectiveType.Short},
        {"hword", DirectiveType.Short},
        {"byte", DirectiveType.Byte},
        {"space", DirectiveType.Space},
        {"skip", DirectiveType.Space},
        {"string", DirectiveType.String},
        {"string8", DirectiveType.String8},
        {"string16", DirectiveType.String16},
        {"2byte", DirectiveType.TwoBytes},
        {"4byte", DirectiveType.FourBytes},
        {"8byte", DirectiveType.EightBytes},
        {"dc", DirectiveType.Dc},
        {"dcb", DirectiveType.Dcb},
        {"ds", DirectiveType.Ds},
        {"ascii", DirectiveType.Ascii},
        {"asciz", DirectiveType.AsciiZ}
    };

    private static readonly string[] KnownDirectives = {""};

    public DirectiveAnalyser()
    {
        foreach (var directive in KnownDirectives)
        {
            _directiveTypes.Add(directive, DirectiveType.Other);
        }
    }

    public AnalysedDirective AnalyseDirective(string directiveText, int directiveStartLinePosition,
        ISourceAnalyser sourceAnalyser)
    {
        if (sourceAnalyser is not SourceAnalyser analyser)
            throw new ArgumentException("Invalid source analyser type.", nameof(sourceAnalyser));

        var lineIndex = analyser.Context.CurrentLineIndex;

        directiveText = directiveText[1..];

        var directiveLastCharIndex = directiveText.IndexOfAny(new[] {' ', '\n', '.', '\t'}) - 1;
        if (directiveLastCharIndex < 0)
            directiveLastCharIndex = directiveText.Length - 1;

        var directive = directiveText[..(directiveLastCharIndex + 1)];
        var parameters = directiveText[(directiveLastCharIndex + 1)..].Trim();

        var directiveRange = new Range(lineIndex, directiveStartLinePosition, lineIndex,
            directiveStartLinePosition + directiveLastCharIndex + 2);

        var paramsRange = new Range(lineIndex, directiveStartLinePosition + directiveLastCharIndex + 3,
            lineIndex, directiveStartLinePosition + directiveLastCharIndex + 3 + parameters.Length);

        var state = DirectiveState.Valid;
        var expectedWidth = -1;
        var severity = DiagnosticSeverity.Error;

        if (!_directiveTypes.TryGetValue(directive, out var type))
        {
            state = DirectiveState.UnknownDirective;
        }
        else
        {
            this.AnalyseDirective(type, directive, parameters, directiveRange, paramsRange, analyser.Context,
                ref state, ref expectedWidth, ref severity);
        }

        return new AnalysedDirective(type, state, directiveRange, directive, paramsRange,
            parameters, expectedWidth, severity);
    }

    private void AnalyseDirective(DirectiveType type, string directive, string parameters,
        Range directiveRange, Range paramsRange, AnalysisContext context,
        ref DirectiveState state, ref int expectedWidth, ref DiagnosticSeverity severity)
    {
        if (type == DirectiveType.Other)
            return;

        if (type is DirectiveType.SetSymbol or DirectiveType.SetUndefinedSymbol)
        {
            // TODO: check symbol name
            var parts = parameters.Split(',');
            if (parts.Length != 2 || string.IsNullOrWhiteSpace(parts[1]))
            {
                state = DirectiveState.InvalidDirectiveSyntax;
                return;
            }

            var label = new AnalysedLabel(parts[0], paramsRange.Take(parts[0].Length), context.CurrentLine,
                context.CurrentLineIndex,
                null, type == DirectiveType.SetSymbol, false);

            context.StubLabels.Add(label);
        }

        if (type == DirectiveType.Word)
        {
            if (!int.TryParse(parameters, out _))
            {
                state = DirectiveState.InvalidConstant;
            }

            expectedWidth = 4;
        }
    }
}
