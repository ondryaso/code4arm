// SourceAnalyser.cs
// Author: Ondřej Ondryáš

using System.Text.RegularExpressions;
using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Models.Abstractions;
using Armfors.LanguageServer.Services.Abstractions;
using Microsoft.Extensions.Logging;
using NUnit.Framework.Internal.Execution;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.CodeAnalysis;

public class SourceAnalyser : ISourceAnalyser
{
    private readonly ISource _source;
    private readonly IInstructionProvider _instructionProvider;
    private readonly IDiagnosticsPublisher _diagnosticsPublisher;
    private readonly ILogger<SourceAnalyser> _logger;

    private readonly SemaphoreSlim _analysisSemaphore = new(1);

    private Dictionary<int, AnalysedLine>? _analysisResultLines;
    private Dictionary<string, AnalysedLabel>? _analysisResultLabels;

    public ISource Source => _source;

    private int _analysedVersion = -1;

    internal SourceAnalyser(ISource source, IInstructionProvider instructionProvider,
        IDiagnosticsPublisher diagnosticsPublisher, ILogger<SourceAnalyser> logger)
    {
        _source = source;
        _instructionProvider = instructionProvider;
        _diagnosticsPublisher = diagnosticsPublisher;
        _logger = logger;
    }

    public async Task TriggerFullAnalysis()
    {
        _logger.LogTrace(
            "Full analysis request. Currently analysed version: {AnalysedVersion}. Source version: {SourceVersion}.",
            _analysedVersion, _source.Version);

        if (_analysedVersion >= _source.Version)
        {
            return;
        }

        await _analysisSemaphore.WaitAsync();

        if (_analysedVersion >= _source.Version)
        {
            return;
        }

        _logger.LogDebug("Performing full analysis.");

        try
        {
            // TODO: check and use async variants
            var enumerable = _source.GetLines();

            _lineIndex = -1;
            _state = LineAnalysisState.Empty;

            var capacity = _analysisResultLines != null
                ? _analysisResultLines.Count + (_analysisResultLines.Count >> 2)
                : 16;

            var newLineCache =
                new Dictionary<int, AnalysedLine>(capacity);
            var newLabels = new Dictionary<string, AnalysedLabel>(_analysisResultLabels?.Count ?? 4);
            var labelsStart = -1;

            foreach (var line in enumerable)
            {
                await this.AnalyseNextLine(line);
                newLineCache.Add(_lineIndex, _currentLine!);

                if (labelsStart == -1 && _currentLine!.State == LineAnalysisState.Blank && _labelsToAppend.Count > 0)
                {
                    _logger.LogTrace("Series of labels starting at [{Index}].", _lineIndex);
                    labelsStart = _lineIndex;
                }
                else if (_currentLine!.State != LineAnalysisState.Blank && _labelsToAppend.Count > 0)
                {
                    _logger.LogTrace("Series of labels terminating at [{Index}].", _lineIndex);
                    foreach (var label in _labelsToAppend)
                    {
                        var isAlreadyDefined = newLabels.TryGetValue(label.Label, out var alreadyDefined);

                        var populatedLabel = label with
                        {
                            PointsTo = _currentLine,
                            RedefinedFrom = isAlreadyDefined ? alreadyDefined.Range.Start.Line : null
                        };

                        _currentLine.Labels.Add(populatedLabel);
                        if (labelsStart != -1)
                        {
                            for (var i = labelsStart; i < _lineIndex; i++)
                            {
                                newLineCache[i].Labels.Add(populatedLabel);
                            }
                        }
                    }

                    _labelsToAppend.Clear();
                    labelsStart = -1;
                }
            }

            _analysedVersion = _source.Version ?? -1;
            _analysisResultLines = newLineCache;
            _analysisResultLabels = newLabels;

            _logger.LogDebug("Analysis done. {Lines} lines, {Labels} labels. Analysed version: {AnalysedVersion}.",
                newLineCache.Count, newLabels.Count, _analysedVersion);
        }
        finally
        {
            _analysisSemaphore.Release();
            _logger.LogTrace("Lock released.");
        }

        await _diagnosticsPublisher.PublishAnalysisResult(this, _source.Uri, _analysedVersion).ConfigureAwait(false);
    }

    public Task TriggerLineAnalysis(int line, bool added)
    {
        // TODO
        throw new NotImplementedException();
    }

    public AnalysedLine? GetLineAnalysis(int line)
    {
        return _analysisResultLines?[line];
    }

    public IEnumerable<AnalysedLine> GetLineAnalyses()
    {
        return _analysisResultLines?.OrderBy(c => c.Key).Select(c => c.Value)
               ?? Enumerable.Empty<AnalysedLine>();
    }

    public IEnumerable<AnalysedLabel> GetLabels()
    {
        return _analysisResultLabels?.Values ?? Enumerable.Empty<AnalysedLabel>();
    }

    public AnalysedLabel? GetLabel(string name)
    {
        return (_analysisResultLabels?.TryGetValue(name, out var val) ?? false) ? val : null;
    }

    private LineAnalysisState _state = LineAnalysisState.Empty;

    private int _lineIndex = -1;
    private AnalysedLine? _currentLine;
    private readonly List<AnalysedLabel> _labelsToAppend = new();

    private async Task AnalyseNextLine(string line)
    {
        var currentLineIndex = ++_lineIndex;
        var loadingSpecifierStart = -1;
        var textStart = 0;

        _currentLine = new AnalysedLine(currentLineIndex, line.Length);

        _logger.LogTrace("Analysing line [{Index}]: {Line}.", currentLineIndex, line);

        for (var linePos = 0; linePos < line.Length; linePos++)
        {
            var consumedPart = new System.Range(textStart, linePos + 1);

            var c = line[linePos];
            switch (_state)
            {
                case LineAnalysisState.Empty:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(linePos, LineAnalysisState.Blank);
                        return;
                    }
                    else if (char.IsWhiteSpace(c))
                    {
                        // Keeping the state Empty
                        break;
                    }
                    else if (!IsValidSymbolChar(c, true))
                    {
                        _state = LineAnalysisState.SyntaxError;
                    }
                    else
                    {
                        // First character loaded, begin mnemonic analysis
                        textStart = linePos;
                        consumedPart = new System.Range(textStart, linePos + 1);
                        _currentLine.StartCharacter = linePos;
                        _state = await this.AnalyseMatchingMnemonics(line, consumedPart);
                    }

                    break;
                case LineAnalysisState.HasMatches:
                    if (c is '\n' or ' ')
                    {
                        // There's no full match -> the string is not a valid mnemonic -> there's no point
                        // in analysing the rest of the line
                        this.FinishCurrentLine(linePos, LineAnalysisState.InvalidMnemonic);
                        return;
                    }
                    else if (c == ':')
                    {
                        this.HandleLabel(line, linePos, ref textStart);
                    }
                    else if (!IsValidSymbolChar(c))
                    {
                        _state = LineAnalysisState.SyntaxError;
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
                        this.FinishCurrentLine(linePos, this.DetermineMnemonicValidity(line));
                        return;
                    }
                    else if (c == ':')
                    {
                        this.HandleLabel(line, linePos, ref textStart);
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

                                _currentLine.ConditionCodeRange = new Range(currentLineIndex, linePos, currentLineIndex,
                                    linePos + 1);
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
                    else if (!IsValidSymbolChar(c))
                    {
                        _state = LineAnalysisState.SyntaxError;
                    }
                    else
                    {
                        _state = await this.AnalyseMatchingMnemonics(line, consumedPart);
                        this.ResetCurrentLineFlags();
                    }

                    break;
                case LineAnalysisState.PossibleConditionCode:
                {
                    if (c == ':')
                    {
                        this.HandleLabel(line, linePos, ref textStart);
                        break;
                    }

                    var ccPart = line[(linePos - 1)..(linePos + 1)];

                    if (Enum.TryParse(ccPart, true, out ConditionCode cc) && Enum.IsDefined(typeof(ConditionCode), cc))
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
                    if (c == ':')
                    {
                        this.HandleLabel(line, linePos, ref textStart);
                        break;
                    }

                    if (!IsValidSymbolChar(c))
                    {
                        _state = LineAnalysisState.SyntaxError;
                        break;
                    }

                    var range = (loadingSpecifierStart + 1)..(linePos + 1);
                    _state = this.DetermineSpecifierValidity(line, range);
                }
                    break;
                case LineAnalysisState.InvalidSpecifier:
                case LineAnalysisState.SpecifierSyntaxError:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(linePos, _state);
                    }
                    else if (c == ':')
                    {
                        this.HandleLabel(line, linePos, ref textStart);
                    }

                    break;
                case LineAnalysisState.InvalidMnemonic:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(linePos, LineAnalysisState.InvalidMnemonic);
                        return;
                    }
                    else if (c == ':')
                    {
                        this.HandleLabel(line, linePos, ref textStart);
                    }

                    // At this state, there's no possibility of finding a new matching mnemonic by consuming more characters
                    // -> we can just stay here until the whole line is terminated
                    // TODO: fast-forward this line to its end (adjust _currentPosition)

                    break;
                case LineAnalysisState.MnemonicLoaded:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(linePos, this.DetermineMnemonicValidity(line));
                        return;
                    }
                    else if (c == ' ')
                    {
                        // Staying here
                        break;
                    }
                    else
                    {
                        this.AnalyseOperandsAndFinishLine(line, linePos);
                        return;
                    }
                case LineAnalysisState.InvalidOperands:
                case LineAnalysisState.SyntaxError:
                    //if (c == '\n')
                {
                    this.FinishCurrentLine(linePos, LineAnalysisState.SyntaxError);
                    return;
                }

                    break;
                case LineAnalysisState.ValidLine:
                case LineAnalysisState.OperandAnalysis:
                case LineAnalysisState.Blank:
                    throw new InvalidOperationException($"FSM state cannot be {_state.ToString()}");
                default:
                    throw new InvalidOperationException($"Invalid FSM state value: {_state}.");
            }
        }

        if (_currentLine.State == LineAnalysisState.Empty && line.EndsWith('\n'))
        {
            this.FinishCurrentLine(line.Length - 1, _state);
        }
    }

    private void HandleLabel(string line, int linePos, ref int textStart)
    {
        _currentLine!.Mnemonic = null;
        _currentLine.MnemonicRange = null;
        _currentLine.MatchingMnemonics = new List<InstructionVariant>();

        this.ResetCurrentLineFlags();

        var labelStub = new AnalysedLabel(line[textStart..linePos], new Range(_lineIndex,
            textStart, _lineIndex, linePos), null);

        _labelsToAppend.Add(labelStub);

        // Label loaded, reset FSM to the start
        textStart = linePos + 1;
        _state = LineAnalysisState.Empty;
    }

    private void FinishCurrentLine(int linePos, LineAnalysisState endState)
    {
        _state = LineAnalysisState.Empty;
        _currentLine!.State = endState;
        _currentLine!.EndCharacter = linePos;
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
        if (_currentLine.Mnemonic.HasOperands && _currentLine.Mnemonic.Operands.Any(o => !o.Optional))
        {
            _currentLine.MissingOperands = true;
            _currentLine.ErroneousOperandIndex = 0;

            return LineAnalysisState.InvalidOperands;
        }

        return LineAnalysisState.ValidLine;
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
        var lineRange = new Range(_lineIndex, consumedRange.Start.Value - 1, _lineIndex,
            consumedRange.End.Value);

        if (Enum.TryParse(specifier, true, out InstructionSize instructionSize) &&
            Enum.IsDefined(typeof(InstructionSize), instructionSize))
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

        var allVectorTypes = Enum.GetValues<VectorDataType>();
        foreach (var vectorType in allVectorTypes)
        {
            var textForm = vectorType.GetTextForm();

            if (textForm.Equals(specifier, StringComparison.InvariantCultureIgnoreCase))
            {
                var spec = new AnalysedSpecifier(specifier, lineRange, vector, specifierIndex, false);

                _currentLine.Specifiers.Add(spec);
                return LineAnalysisState.InvalidSpecifier;
            }

            if (textForm.StartsWith(specifier, StringComparison.InvariantCultureIgnoreCase))
            {
                return LineAnalysisState.LoadingSpecifier;
            }
        }

        _currentLine.Specifiers.Add(new AnalysedSpecifier(specifier, lineRange));
        return LineAnalysisState.SpecifierSyntaxError;
    }

    private readonly Regex _commaRegex = new("\\G ?, ?", RegexOptions.Compiled);
    private readonly Regex _endLineRegex = new("\\G ?$", RegexOptions.Compiled | RegexOptions.Multiline);

    private void AnalyseOperandsAndFinishLine(string line, int linePos)
    {
        var opPart = line[linePos..];
        var mnemonic = _currentLine!.Mnemonic!;
        var opDescriptors = mnemonic.Operands;

        if (opDescriptors.IsEmpty)
        {
            if (opPart.Trim().Length != 0)
            {
                _currentLine.NoOperandsAllowed = true;
                this.FinishCurrentLine(linePos, LineAnalysisState.InvalidOperands);
            }
            else
            {
                this.FinishCurrentLine(linePos, LineAnalysisState.ValidLine);
            }

            return;
        }

        if (opDescriptors.Any(o => !o.Optional) && opPart.Trim().Length == 0)
        {
            _currentLine.MissingOperands = true;
            _currentLine.ErroneousOperandIndex = 0;

            this.FinishCurrentLine(linePos, LineAnalysisState.InvalidOperands);
            return;
        }

        _currentLine.Operands = new List<AnalysedOperand>();

        var opPartPos = 0;
        var resultOpIndexShift = 0;

        for (var opIndex = 0; opIndex < opDescriptors.Count; opIndex++)
        {
            var descriptor = opDescriptors[opIndex];
            var match = descriptor.Regex.Match(opPart, opPartPos);
            var resultOpIndex = opIndex - resultOpIndexShift;

            if (match.Success && match.Index == opPartPos)
            {
                var range = new Range(_lineIndex, linePos + opPartPos, _lineIndex,
                    linePos + opPartPos + match.Length);
                var analysed = this.CheckOperand(resultOpIndex, descriptor, match, range);

                _currentLine.Operands.Add(analysed);

                if (analysed.Result != OperandResult.Valid)
                {
                    // Invalid operand -> terminate analysis altogether
                    _currentLine.ErroneousOperandIndex = resultOpIndex;
                    this.FinishCurrentLine(linePos, LineAnalysisState.InvalidOperands);
                    return;
                }

                opPartPos += match.Length;
            }
            else if (descriptor.Optional)
            {
                resultOpIndexShift++;
                
                if (CheckLineEnd(opIndex, resultOpIndex))
                    return;
                
                continue;
            }
            else
            {
                var range = new Range(_lineIndex, linePos + opPartPos, _lineIndex,
                    line.Length);
                var analysed = new AnalysedOperand(resultOpIndex, descriptor, range, OperandResult.SyntaxError, range);

                _currentLine.Operands.Add(analysed);
                _currentLine.ErroneousOperandIndex = resultOpIndex;

                this.FinishCurrentLine(linePos, LineAnalysisState.InvalidOperands);
                return;
            }

            match = _commaRegex.Match(opPart, opPartPos);
            if (match.Success)
            {
                if (opIndex == opDescriptors.Count - 1)
                {
                    // Comma after the last operand
                    var range = new Range(_lineIndex, linePos + opPartPos, _lineIndex,
                        line.Length);
                    var analysed = new AnalysedOperand(resultOpIndex + 1, descriptor, range, OperandResult.SyntaxError,
                        range);
                    _currentLine.Operands.Add(analysed);
                    _currentLine.ErroneousOperandIndex = resultOpIndex + 1;

                    this.FinishCurrentLine(linePos, LineAnalysisState.InvalidOperands);
                    return;
                }
                else
                {
                    // Consume a comma between operands
                    opPartPos += match.Length;
                }
            }

            if (CheckLineEnd(opIndex, resultOpIndex))
                return;
        }

        bool CheckLineEnd(int opIndex, int resultOpIndex)
        {
            if (_endLineRegex.IsMatch(opPart, opPartPos))
            {
                if (opIndex == opDescriptors.Count - 1)
                {
                    // End of line after the last operand
                    this.FinishCurrentLine(linePos, LineAnalysisState.ValidLine);
                    return true;
                }
                else if (opDescriptors.Skip(opIndex + 1).Any(o => !o.Optional))
                {
                    // End of line after an operand in the middle
                    _currentLine.MissingOperands = true;
                    _currentLine.ErroneousOperandIndex = resultOpIndex + 1;
                    this.FinishCurrentLine(linePos, LineAnalysisState.InvalidOperands);
                    return true;
                }
            }

            return false;
        }
    }

    private AnalysedOperand CheckOperand(int opIndex, OperandDescriptor descriptor, Match match, Range range)
    {
        // TODO
        return new AnalysedOperand(opIndex, descriptor, range, OperandResult.Valid);
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

    private static bool IsValidSymbolChar(char c, bool firstChar = false) =>
        (firstChar ? char.IsLetter(c) : char.IsLetterOrDigit(c)) || c is '_' or '.' or '$';
}
