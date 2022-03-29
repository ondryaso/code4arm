using System.Collections.Immutable;
using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.CodeAnalysis;

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
        {"equ", DirectiveType.Equ},
        {"equiv", DirectiveType.Equiv},
        {"eqv", DirectiveType.Eqv},
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
        int lineIndex)
    {
        directiveText = directiveText[1..];
        
        var directiveLastCharIndex = directiveText.IndexOfAny(new[] {' ', '\n', '.'}) - 1;
        if (directiveLastCharIndex < 0)
            directiveLastCharIndex = directiveText.Length - 1;

        var directive = directiveText[..(directiveLastCharIndex + 1)];
        var parameters = directiveText[(directiveLastCharIndex + 1)..].Trim();

        var directiveRange = new Range(lineIndex, directiveStartLinePosition, lineIndex,
            directiveStartLinePosition + directiveLastCharIndex + 2);

        var paramsRange = new Range(lineIndex, directiveStartLinePosition + directiveLastCharIndex + 2,
            lineIndex, directiveStartLinePosition + directiveText.Length);

        var state = DirectiveState.Valid;
        var expectedWidth = -1;
        var severity = DiagnosticSeverity.Error;

        if (!_directiveTypes.TryGetValue(directive, out var type))
        {
            state = DirectiveState.UnknownDirective;
        }
        else
        {
            this.AnalyseDirective(type, directive, parameters, ref state, ref expectedWidth, ref severity);
        }

        return new AnalysedDirective(type, state, directiveRange, directive, paramsRange,
            parameters, expectedWidth, severity);
    }

    private void AnalyseDirective(DirectiveType type, string directive, string parameters,
        ref DirectiveState state, ref int expectedWidth, ref DiagnosticSeverity severity)
    {
        if (type == DirectiveType.Other)
            return;

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