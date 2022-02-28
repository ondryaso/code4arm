// SourceAnalyser.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Models.Abstractions;
using Microsoft.Extensions.Logging;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.CodeAnalysis;

public class SourceAnalyser : ISourceAnalyser
{
    private readonly ISource _source;
    private readonly IInstructionProvider _instructionProvider;
    private readonly ILogger<SourceAnalyser> _logger;
    private readonly Dictionary<int, AnalysedLine> _lineCache = new();

    public ISource Source => _source;

    internal SourceAnalyser(ISource source, IInstructionProvider instructionProvider, ILogger<SourceAnalyser> logger)
    {
        _source = source;
        _instructionProvider = instructionProvider;
        _logger = logger;
    }

    public async Task TriggerFullAnalysis()
    {
        // TODO: check and use async variants
        var enumerable = _source.GetLines();
        
        _sourcePosition = 0;
        _lineIndex = 0;
        
        foreach (var line in enumerable)
        {
            await this.AnalyseNextLine(line);
            _lineCache.Add(_lineIndex - 1, _currentLine);
        }
    }

    public async Task TriggerLineAnalysis(int line, bool added)
    {
        await this.TriggerFullAnalysis();
    }

    public Task<AnalysedLine> GetLineAnalysis(int line)
    {
        return Task.FromResult(new AnalysedLine(0, 0, 0, LineAnalysisState.Blank));
    }

    private LineAnalysisState _state = LineAnalysisState.Empty;

    private int _sourcePosition = 0;
    private int _lineIndex = 0;
    private AnalysedLine? _currentLine;

    private async Task AnalyseNextLine(string line)
    {
        _currentLine = new AnalysedLine(_lineIndex);

        var currentLineIndex = _lineIndex++;
        var loadingSpecifierStart = -1;
        var textStart = 0;

        for (var linePos = 0; linePos < line.Length; linePos++)
        {
            var consumedPart = new System.Range(textStart, linePos + 1);

            var c = line[linePos];
            switch (_state)
            {
                case LineAnalysisState.Empty:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(LineAnalysisState.Blank);
                        return;
                    }
                    else if (char.IsWhiteSpace(c))
                    {
                        // Keeping the state Empty
                        break;
                    }
                    else
                    {
                        textStart = linePos;
                        consumedPart = new System.Range(textStart, linePos + 1);
                        _state = await this.AnalyseMatchingMnemonics(line, consumedPart);
                    }

                    break;
                case LineAnalysisState.HasMatches:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(LineAnalysisState.InvalidMnemonic);
                        return;
                    }
                    else if (c == ' ')
                    {
                        // There's no full match -> the string is not a valid mnemonic -> there's no point
                        // in analysing the rest of the line
                        this.FinishCurrentLine(LineAnalysisState.InvalidMnemonic);
                        return;
                    }
                    else
                    {
                        _state = await this.AnalyseMatchingMnemonics(line, consumedPart);
                    }

                    break;
                case LineAnalysisState.HasFullMatch:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(this.DetermineMnemonicValidity(line));
                        return;
                    }
                    else if (c is 'S' or 's')
                    {
                        var mnemonic = _currentLine.Mnemonic!;
                        if (mnemonic.HasSetFlagsVariant)
                        {
                            if (_currentLine.SetsFlags)
                            {
                                _currentLine.MnemonicFinished = false;
                                _state = await this.AnalyseMatchingMnemonics(line, consumedPart);

                                if (_state is not LineAnalysisState.InvalidMnemonic) // TODO: think about this condition
                                {
                                    _currentLine.SetsFlags = false;
                                    _currentLine.SetFlagsRange = null;
                                }

                                break;
                            }

                            _currentLine.MnemonicFinished = true;
                            _currentLine.SetsFlags = true;
                            _currentLine.SetFlagsRange = new Range(currentLineIndex, linePos, currentLineIndex,
                                linePos);
                        }
                        else
                        {
                            // E.g. there's non-S-able XYZ and a different mnemonic XYZSW
                            _state = await this.AnalyseMatchingMnemonics(line, consumedPart);

                            if (_state == LineAnalysisState.InvalidMnemonic)
                            {
                                // This seems to be an attempt to -S a non-S-able instruction
                                // Set the position of the S to signalise to the user
                                _currentLine.SetFlagsRange = new Range(currentLineIndex, linePos, currentLineIndex,
                                    linePos);
                                _currentLine.CannotSetFlags = true;
                            }
                        }
                    }
                    else if (StartsConditionCode(c))
                    {
                        var mnemonic = _currentLine.Mnemonic!;
                        if (mnemonic.CanBeConditional)
                        {
                            if (_currentLine.IsConditional)
                            {
                                _state = await this.AnalyseMatchingMnemonics(line, consumedPart);

                                if (_state is not LineAnalysisState.InvalidMnemonic) // TODO: think about this condition
                                {
                                    _currentLine.ConditionCode = null;
                                    _currentLine.ConditionCodeRange = null;
                                }

                                break;
                            }

                            _currentLine.MnemonicFinished = false;
                            _state = LineAnalysisState.PossibleConditionCode;
                        }
                        else
                        {
                            _state = await this.AnalyseMatchingMnemonics(line, consumedPart);

                            if (_state == LineAnalysisState.InvalidMnemonic)
                            {
                                // This seems to be an attempt to add condition code to an unconditional instruction
                                // Set the position of the condition code to signalise to the user
                                _currentLine.ConditionCodeRange = new Range(currentLineIndex, linePos, currentLineIndex,
                                    (linePos + 2) >= line.Length ? linePos : (linePos + 1));
                                _currentLine.CannotBeConditional = true;
                            }
                        }
                    }
                    else if (c == '.')
                    {
                        // Vector (preferred) or qualifier (.W/.N)
                        _currentLine.MnemonicFinished = false;
                        _state = LineAnalysisState.LoadingSpecifier;
                        loadingSpecifierStart = linePos;
                    }
                    else if (c == ' ')
                    {
                        _currentLine.MnemonicFinished = true;
                        _state = LineAnalysisState.MnemonicLoaded;
                    }
                    else
                    {
                        _currentLine.MnemonicFinished = false;
                        _state = await this.AnalyseMatchingMnemonics(line, consumedPart);
                    }

                    break;
                case LineAnalysisState.InvalidMnemonic:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(LineAnalysisState.InvalidMnemonic);
                        return;
                    }

                    // At this state, there's no possibility of finding a new matching mnemonic by consuming more characters
                    // -> we can just stay here until the whole line is terminated
                    // TODO: fast-forward this line to its end (adjust _currentPosition)

                    break;
                case LineAnalysisState.ValidLine:
                    throw new InvalidOperationException($"FSM state cannot be {nameof(LineAnalysisState.ValidLine)}");
                case LineAnalysisState.PossibleConditionCode:
                {
                    var ccPart = line[(linePos - 1)..(linePos + 1)];
                    if (Enum.TryParse(ccPart, out ConditionCode cc))
                    {
                        _currentLine.ConditionCode = cc;
                        _currentLine.ConditionCodeRange =
                            new Range(currentLineIndex, linePos - 1, currentLineIndex, linePos);
                        _state = LineAnalysisState.HasFullMatch;
                        _currentLine.MnemonicFinished = true;
                    }
                    else if (c is '\n' or ' ')
                    {
                        // There might still be other valid instructions.
                        // Go one step back and behave as if there wasn't a condition code
                        _state = await this.AnalyseMatchingMnemonics(line, new System.Range(textStart, linePos));
                        linePos--;
                        _sourcePosition--;
                    }
                }
                    break;
                case LineAnalysisState.LoadingSpecifier:
                {
                    var range = (loadingSpecifierStart + 1)..(linePos + 1);
                    _state = this.DetermineSpecifierValidity(line, range);
                }
                    break;
                case LineAnalysisState.InvalidSpecifier:
                case LineAnalysisState.SpecifierSyntaxError:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine();
                        return;
                    }

                    break;
                case LineAnalysisState.MnemonicLoaded:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(this.DetermineMnemonicValidity(line));
                        return;
                    }
                    else if (c == ' ')
                    {
                        // Staying here
                        break;
                    }
                    else
                    {
                        _state = LineAnalysisState.OperandAnalysis;
                    }

                    break;
                case LineAnalysisState.OperandAnalysis:
                    _state = this.AnalyseOperands(line[linePos..]);
                    break;
                case LineAnalysisState.InvalidOperands:
                case LineAnalysisState.SyntaxError:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine();
                        return;
                    }

                    break;
                case LineAnalysisState.Blank:
                    throw new InvalidOperationException("FSM state cannot be 'Blank'.");
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }
    }

    private void FinishCurrentLine(LineAnalysisState? endState = null)
    {
        _currentLine!.EndCharacter = _sourcePosition - 1;
        _state = LineAnalysisState.Empty;

        if (endState.HasValue)
        {
            _currentLine.State = endState.Value;
        }
    }

    private async Task<LineAnalysisState> AnalyseMatchingMnemonics(string line, System.Range consumedRange)
    {
        var linePart = line[consumedRange];
        var mnemonics = await _instructionProvider.FindMatchingInstructions(linePart);
        _currentLine!.MatchingMnemonics = mnemonics;

        if (mnemonics.Count == 0)
        {
            _currentLine.Mnemonic = null;
            _currentLine.MnemonicRange = null;
            _currentLine.MnemonicFinished = false;

            return LineAnalysisState.InvalidMnemonic;
        }

        var fullMatch = mnemonics.FirstOrDefault(m =>
            m.Mnemonic.Equals(linePart.Trim(), StringComparison.InvariantCultureIgnoreCase));

        if (fullMatch != null)
        {
            _currentLine.Mnemonic = fullMatch;
            _currentLine.MnemonicRange =
                new Range(_lineIndex, consumedRange.Start.Value, _lineIndex, consumedRange.End.Value);
            return LineAnalysisState.HasFullMatch;
        }

        return LineAnalysisState.HasMatches;
    }

    private LineAnalysisState DetermineMnemonicValidity(string line)
    {
        // Doesn't need operands -> ValidLine
        // Needs operands -> InvalidOperands

        if (_currentLine?.Mnemonic == null)
        {
            return LineAnalysisState.InvalidMnemonic;
        }

        // TODO: this has to check if the syntax is valid
        return _currentLine.Mnemonic.HasOperands ? LineAnalysisState.InvalidOperands : LineAnalysisState.ValidLine;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <returns>LoadingSpecifier or InvalidSpecifier or SpecifierSyntaxError or HasFullMatch.</returns>
    private LineAnalysisState DetermineSpecifierValidity(string line, System.Range consumedRange)
    {
        var specifier = line[consumedRange];
        var m = _currentLine!.Mnemonic!;
        var specifierIndex = _currentLine.Specifiers.Count;
        var lineRange = new Range(_lineIndex, consumedRange.Start.Value - 1, _lineIndex, consumedRange.End.Value);

        if (Enum.TryParse(specifier, true, out InstructionSize instructionSize))
        {
            var allowed = specifierIndex == 0 &&
                          (!m.ForcedSize.HasValue || m.ForcedSize.Value == instructionSize);

            var spec = new AnalysedSpecifier(specifier, lineRange,
                instructionSize, allowed);

            _currentLine.Specifiers.Add(spec);
            return allowed ? LineAnalysisState.HasFullMatch : LineAnalysisState.InvalidSpecifier;
        }

        var vector = VectorDataTypeExtensions.GetVectorDataType(specifier);
        if (vector != VectorDataType.Unknown)
        {
            var allowed = m.IsVectorDataTypeAllowed(specifierIndex, vector);
            var spec = new AnalysedSpecifier(specifier, lineRange, vector, specifierIndex, allowed);

            _currentLine.Specifiers.Add(spec);
            return allowed ? LineAnalysisState.HasFullMatch : LineAnalysisState.InvalidSpecifier;
        }

        var possibleVectorTypes = m.GetPossibleVectorDataTypes(specifierIndex);
        foreach (var possibleVectorType in possibleVectorTypes)
        {
            if (possibleVectorType.GetTextForm().StartsWith(specifier, StringComparison.InvariantCultureIgnoreCase))
            {
                return LineAnalysisState.LoadingSpecifier;
            }
        }

        return LineAnalysisState.SpecifierSyntaxError;
    }

    private LineAnalysisState AnalyseOperands(string operandsPart)
    {
        // TODO
        return LineAnalysisState.ValidLine;
    }

    private static readonly char[] ConditionCodeStarts =
    {
        'E', 'e', 'N', 'n', 'C', 'c', 'H', 'h', 'L', 'l', 'M', 'm',
        'P', 'p', 'V', 'v', 'G', 'g', 'A', 'a'
    };

    private static bool StartsConditionCode(char c) => ConditionCodeStarts.Contains(c);
}
