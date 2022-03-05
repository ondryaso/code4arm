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
    private readonly SemaphoreSlim _analysisSemaphore = new(1);
    public ISource Source => _source;

    private int _analysedVersion = -1;

    internal SourceAnalyser(ISource source, IInstructionProvider instructionProvider, ILogger<SourceAnalyser> logger)
    {
        _source = source;
        _instructionProvider = instructionProvider;
        _logger = logger;
    }

    public async Task TriggerFullAnalysis()
    {
        if (_analysedVersion >= _source.Version)
        {
            return;
        }

        await _analysisSemaphore.WaitAsync();

        if (_analysedVersion >= _source.Version)
        {
            return;
        }

        _logger.LogWarning("Performing full analysis");

        try
        {
            // TODO: check and use async variants
            var enumerable = _source.GetLines();

            _sourcePosition = 0;
            _lineIndex = 0;

            _lineCache.Clear();
            foreach (var line in enumerable)
            {
                await this.AnalyseNextLine(line);
                _lineCache.Add(_lineIndex - 1, _currentLine);
            }

            _analysedVersion = _source.Version ?? -1;
        }
        finally
        {
            _analysisSemaphore.Release();
        }
    }

    public async Task TriggerLineAnalysis(int line, bool added)
    {
        await this.TriggerFullAnalysis();
    }

    public AnalysedLine GetLineAnalysis(int line)
    {
        return _lineCache[line];
    }

    public IEnumerable<AnalysedLine> GetLineAnalyses()
    {
        _analysisSemaphore.Wait();

        try
        {
            return _lineCache.OrderBy(c => c.Key).Select(c => c.Value);
        }
        finally
        {
            _analysisSemaphore.Release();
        }
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
                        // First character loaded, begin mnemonic analysis
                        textStart = linePos;
                        consumedPart = new System.Range(textStart, linePos + 1);
                        _state = await this.AnalyseMatchingMnemonics(line, consumedPart);
                    }

                    break;
                case LineAnalysisState.HasMatches:
                    if (c is '\n' or ' ')
                    {
                        // There's no full match -> the string is not a valid mnemonic -> there's no point
                        // in analysing the rest of the line
                        this.FinishCurrentLine(LineAnalysisState.InvalidMnemonic);
                        return;
                    }
                    else
                    {
                        // Analyse further
                        _state = await this.AnalyseMatchingMnemonics(line, consumedPart);
                    }

                    break;
                case LineAnalysisState.HasFullMatch:
                    // _currentLine.Mnemonic has been populated by the previous run of AnalyseMatchingMnemonics 
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(this.DetermineMnemonicValidity(line));
                        return;
                    }
                    else if (c is 'S' or 's' && !_currentLine.HasConditionCodePart &&
                             _currentLine.Specifiers.Count == 0)
                    {
                        var mnemonic = _currentLine.Mnemonic!;
                        if (mnemonic.HasSetFlagsVariant)
                        {
                            if (_currentLine.SetsFlags)
                            {
                                // E.g. there's an S-able XYZS and a different mnemonic XYZSS
                                _currentLine.SetsFlags = false;
                                _currentLine.SetFlagsRange = null;
                                _currentLine.CannotSetFlags = false;

                                _state = await this.AnalyseMatchingMnemonics(line, consumedPart);

                                break;
                            }

                            _currentLine.SetsFlags = true;
                            _currentLine.SetFlagsRange = new Range(currentLineIndex, linePos, currentLineIndex,
                                linePos + 1);
                            _currentLine.CannotSetFlags = false;
                        }
                        else
                        {
                            // E.g. there's non-S-able XYZ and a different mnemonic XYZSW
                            _state = await this.AnalyseMatchingMnemonics(line, consumedPart, false);

                            if (_state == LineAnalysisState.InvalidMnemonic)
                            {
                                // This seems to be an attempt to -S a non-S-able instruction
                                // Set the position of the S to signalise to the user
                                _currentLine.SetsFlags = false;
                                _currentLine.SetFlagsRange = new Range(currentLineIndex, linePos, currentLineIndex,
                                    linePos + 1);
                                _currentLine.CannotSetFlags = true;
                            }
                            else
                            {
                                this.ResetCurrentLineFlags();
                            }
                        }
                    }
                    else if (StartsConditionCode(c) && !_currentLine.HasConditionCodePart)
                    {
                        var mnemonic = _currentLine.Mnemonic!;
                        if (mnemonic.CanBeConditional)
                        {
                            _state = LineAnalysisState.PossibleConditionCode;
                        }
                        else
                        {
                            // Check if there isn't a matching instruction (XYZ + E when there are XYZ and XYZE would get us here) 
                            var possibleNextState = await this.AnalyseMatchingMnemonics(line, consumedPart, false);

                            if (possibleNextState == LineAnalysisState.InvalidMnemonic)
                            {
                                // This seems to be an attempt to add condition code to an unconditional instruction
                                // Set a flag and pretend it's ok to jump into PossibleConditionCode

                                _currentLine.CannotBeConditional = true;
                                _state = LineAnalysisState.PossibleConditionCode;

                                break;
                            }

                            this.ResetCurrentLineFlags();
                            _state = possibleNextState;
                        }
                    }
                    else if (c == '.')
                    {
                        // Vector (preferred) or qualifier (.W/.N)
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
                        _state = await this.AnalyseMatchingMnemonics(line, consumedPart);
                        this.ResetCurrentLineFlags();
                    }

                    break;
                case LineAnalysisState.PossibleConditionCode:
                {
                    var ccPart = line[(linePos - 1)..(linePos + 1)];

                    if (Enum.TryParse(ccPart, true, out ConditionCode cc))
                    {
                        if (!_currentLine.CannotBeConditional)
                        {
                            _currentLine.ConditionCode = cc;
                        }

                        _currentLine.ConditionCodeRange =
                            new Range(currentLineIndex, linePos - 1, currentLineIndex, linePos + 1);

                        _currentLine.HasInvalidConditionCode = false;
                        _currentLine.HasUnterminatedConditionCode = false;

                        _state = LineAnalysisState.HasFullMatch;
                        break;
                    }

                    _currentLine.ConditionCode = null;

                    // There might still be other valid instructions.
                    var possibleNextState =
                        await this.AnalyseMatchingMnemonics(line, new System.Range(textStart, linePos), false);

                    if (possibleNextState == LineAnalysisState.InvalidMnemonic)
                    {
                        _currentLine.ConditionCodeRange =
                            new Range(currentLineIndex, linePos - 1, currentLineIndex, linePos + 1);

                        if (c is '\n' or ' ')
                        {
                            _currentLine.HasUnterminatedConditionCode = true;

                            // Move one char back to handle mnemonic termination properly in HasFullMatch in the next iteration
                            _sourcePosition--;
                            linePos--;
                        }
                        else
                        {
                            _currentLine.HasInvalidConditionCode = true;
                        }

                        // Pretend everything's OK
                        _state = LineAnalysisState.HasFullMatch;

                        break;
                    }

                    // There's another valid instruction
                    this.ResetCurrentLineFlags();
                    _state = possibleNextState;
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
                        linePos--;
                        _sourcePosition--;
                        _state = LineAnalysisState.OperandAnalysis;
                    }

                    break;
                case LineAnalysisState.OperandAnalysis:
                    this.AnalyseOperandsAndFinishLine(line[linePos..]);
                    return;
                case LineAnalysisState.InvalidOperands:
                case LineAnalysisState.SyntaxError:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine();
                        return;
                    }

                    break;
                case LineAnalysisState.ValidLine:
                    throw new InvalidOperationException($"FSM state cannot be {nameof(LineAnalysisState.ValidLine)}");
                case LineAnalysisState.Blank:
                    throw new InvalidOperationException($"FSM state cannot be {nameof(LineAnalysisState.Blank)}.");
                default:
                    throw new InvalidOperationException($"Invalid FSM state value: {_state}.");
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

    /// <summary>
    /// TODO
    /// </summary>
    /// <returns>InvalidMnemonic (no matches), HasMatches (possible mnemonics but no full match), HasFullMatch (the current
    /// range of the text contains a valid mnemonic).</returns>
    private async Task<LineAnalysisState> AnalyseMatchingMnemonics(string line, System.Range consumedRange,
        bool clearMatch = true)
    {
        var linePart = line[consumedRange];

        var mnemonics = await _instructionProvider.FindMatchingInstructions(linePart);
        _currentLine!.MatchingMnemonics = mnemonics;

        if (mnemonics.Count == 0)
        {
            if (clearMatch)
            {
                _currentLine.Mnemonic = null;
                _currentLine.MnemonicRange = null;
            }

            return LineAnalysisState.InvalidMnemonic;
        }

        var fullMatch = mnemonics.FirstOrDefault(m =>
            m.Mnemonic.Equals(linePart.Trim(), StringComparison.InvariantCultureIgnoreCase));

        if (fullMatch != null)
        {
            _currentLine.Mnemonic = fullMatch;
            _currentLine.MnemonicRange =
                new Range(_lineIndex - 1, consumedRange.Start.Value, _lineIndex - 1, consumedRange.End.Value);

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
        var lineRange = new Range(_lineIndex - 1, consumedRange.Start.Value - 1, _lineIndex - 1,
            consumedRange.End.Value);

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

    private void AnalyseOperandsAndFinishLine(string operandsPart)
    {
        // TODO
        this.FinishCurrentLine(LineAnalysisState.ValidLine);
    }

    private void ResetCurrentLineFlags()
    {
        _currentLine!.SetsFlags = false;
        _currentLine.SetFlagsRange = null;
        _currentLine.CannotSetFlags = false;
        _currentLine.ConditionCode = null;
        _currentLine.ConditionCodeRange = null;
        _currentLine.CannotBeConditional = false;
        _currentLine.HasInvalidConditionCode = false;
        _currentLine.HasUnterminatedConditionCode = false;
    }

    private static readonly char[] ConditionCodeStarts =
    {
        'E', 'e', 'N', 'n', 'C', 'c', 'H', 'h', 'L', 'l', 'M', 'm',
        'P', 'p', 'V', 'v', 'G', 'g', 'A', 'a'
    };

    private static bool StartsConditionCode(char c) => ConditionCodeStarts.Contains(c);
}
