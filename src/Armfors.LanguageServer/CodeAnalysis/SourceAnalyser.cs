// SourceAnalyser.cs
// Author: Ondřej Ondryáš

using System.Text.RegularExpressions;
using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Extensions;
using Armfors.LanguageServer.Models.Abstractions;
using Armfors.LanguageServer.Services.Abstractions;
using Microsoft.Extensions.Logging;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.CodeAnalysis;

public class SourceAnalyser : ISourceAnalyser
{
    private readonly ISource _source;
    private readonly IInstructionProvider _instructionProvider;
    private readonly IOperandAnalyserProvider _operandAnalyserProvider;
    private readonly IInstructionValidatorProvider _instructionValidatorProvider;
    private readonly IDiagnosticsPublisher _diagnosticsPublisher;
    private readonly ILogger<SourceAnalyser> _logger;

    private readonly SemaphoreSlim _analysisSemaphore = new(1);

    private Dictionary<int, AnalysedLine>? _analysisResultLines;
    private Dictionary<string, AnalysedLabel>? _analysisResultLabels;

    public ISource Source => _source;

    private int _analysedVersion = -1;

    internal SourceAnalyser(ISource source, IInstructionProvider instructionProvider,
        IOperandAnalyserProvider operandAnalyserProvider, IInstructionValidatorProvider instructionValidatorProvider,
        IDiagnosticsPublisher diagnosticsPublisher, ILogger<SourceAnalyser> logger)
    {
        _source = source;
        _instructionProvider = instructionProvider;
        _operandAnalyserProvider = operandAnalyserProvider;
        _instructionValidatorProvider = instructionValidatorProvider;
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

        _logger.LogWarning("------");
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
                _lineIndex++;

                // TODO: handle line endings in a better way
                _currentLineText = (line.Length == 0 || line[^1] != '\n') ? (line + '\n') : line;
                _unsuccessfulVariants.Clear();

                _secondRun = false;
                await this.AnalyseCurrentLine();
                var bestAttempt = _currentLine;

                while (_currentLine!.State != LineAnalysisState.ValidLine
                       && _currentLine.FullMatches.Count > 1
                       && _currentLine.FullMatches.Count > _unsuccessfulVariants.Count)
                {
                    if (_currentLine.Mnemonic != null)
                    {
                        _unsuccessfulVariants.Add(_currentLine.Mnemonic);
                    }

                    if (bestAttempt?.Operands?.Count <= _currentLine?.Operands?.Count)
                    {
                        bestAttempt = _currentLine;
                    }

                    _secondRun = true;
                    await this.AnalyseCurrentLine();
                }

                if (_currentLine.State != LineAnalysisState.ValidLine)
                {
                    _currentLine = bestAttempt;
                }

                newLineCache.Add(_lineIndex, _currentLine!);

                _logger.LogWarning(
                    $"{_lineIndex}: {_currentLine?.Mnemonic?.Mnemonic} ({_currentLine?.PreFinishState} -> {_currentLine?.State})");

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

                        if (!isAlreadyDefined)
                        {
                            newLabels.Add(label.Label, label);
                        }

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

            var allLabels = newLineCache.Values
                .Where(o => o.State == LineAnalysisState.ValidLine && o.Operands is { Count: > 0 })
                .SelectMany(o => o.Operands!)
                .Where(op => op.Result == OperandResult.Valid && op.Tokens is { Count: > 0 })
                .SelectMany(o => o.Tokens!)
                .Where(t => t.Type == OperandTokenType.Label);

            foreach (var labelToken in allLabels)
            {
                if (!newLabels.ContainsKey(labelToken.Text))
                {
                    labelToken.Result = OperandTokenResult.UndefinedLabel;
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

    public async Task TriggerLineAnalysis(int line, bool added)
    {
        // TODO
        if (_analysedVersion < _source.Version)
        {
            await this.TriggerFullAnalysis();
        }
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
    private string _currentLineText = string.Empty;
    private bool _secondRun = false;

    private List<InstructionVariant> _unsuccessfulVariants = new();

    private readonly List<AnalysedLabel> _labelsToAppend = new();

    private async Task AnalyseCurrentLine()
    {
        var line = _currentLineText;
        var loadingSpecifierStart = -1;
        var textStart = 0;

        _currentLine = new AnalysedLine(_lineIndex, line.Length);

        _logger.LogTrace("Analysing line [{Index}]: {Line}.", _lineIndex, line);

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
                        // ReSharper disable once RedundantJumpStatement
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
                        _state = await this.AnalyseMatchingMnemonics(consumedPart);
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
                        this.HandleLabel(linePos, ref textStart);
                    }
                    else if (!IsValidSymbolChar(c))
                    {
                        _state = LineAnalysisState.SyntaxError;
                    }
                    else
                    {
                        // Analyse further
                        _state = await this.AnalyseMatchingMnemonics(consumedPart);
                    }

                    break;
                case LineAnalysisState.HasFullMatch:
                    // _currentLine.Mnemonic has been populated by the previous run of AnalyseMatchingMnemonics 
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(linePos, this.ValidateSoleMnemonic());
                        return;
                    }
                    else if (c == ':')
                    {
                        this.HandleLabel(linePos, ref textStart);
                    }
                    else if (c is 'S' or 's' && !_currentLine.HasConditionCodePart &&
                             !_currentLine.HasSpecifiers)
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

                                _state = await this.AnalyseMatchingMnemonics(consumedPart);

                                break;
                            }

                            _currentLine.SetsFlags = true;
                            _currentLine.SetFlagsRange = new Range(_lineIndex, linePos, _lineIndex,
                                linePos + 1);
                            _currentLine.CannotSetFlags = false;
                        }
                        else
                        {
                            // E.g. there's non-S-able XYZ and a different mnemonic XYZSW
                            _state = await this.AnalyseMatchingMnemonics(consumedPart, false);

                            if (_state == LineAnalysisState.InvalidMnemonic)
                            {
                                // This seems to be an attempt to -S a non-S-able instruction
                                // Set the position of the S to signalise to the user
                                _currentLine.SetsFlags = false;
                                _currentLine.SetFlagsRange = new Range(_lineIndex, linePos, _lineIndex,
                                    linePos + 1);
                                _currentLine.CannotSetFlags = true;
                            }
                            else
                            {
                                this.ResetCurrentLineFlags();
                            }
                        }
                    }
                    else if (StartsConditionCode(c) && !_currentLine.HasConditionCodePart &&
                             !_currentLine.HasSpecifiers)
                    {
                        var mnemonic = _currentLine.Mnemonic!;
                        if (mnemonic.CanBeConditional)
                        {
                            _state = LineAnalysisState.PossibleConditionCode;
                        }
                        else
                        {
                            // Check if there isn't a matching instruction (XYZ + E when there are XYZ and XYZE would get us here) 
                            var possibleNextState = await this.AnalyseMatchingMnemonics(consumedPart, false);

                            if (possibleNextState == LineAnalysisState.InvalidMnemonic)
                            {
                                // This seems to be an attempt to add condition code to an unconditional instruction
                                // Set a flag and pretend it's ok to jump into PossibleConditionCode

                                _currentLine.ConditionCodeRange = new Range(_lineIndex, linePos, _lineIndex,
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
                        _state = await this.AnalyseMatchingMnemonics(consumedPart);
                        this.ResetCurrentLineFlags();
                    }

                    break;
                case LineAnalysisState.PossibleConditionCode:
                {
                    if (c == ':')
                    {
                        this.HandleLabel(linePos, ref textStart);
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
                            new Range(_lineIndex, linePos - 1, _lineIndex, linePos + 1);

                        _currentLine.HasInvalidConditionCode = false;
                        _currentLine.HasUnterminatedConditionCode = false;

                        _state = LineAnalysisState.HasFullMatch;
                        break;
                    }

                    _currentLine.ConditionCode = null;

                    // There might still be other valid instructions.
                    var possibleNextState =
                        await this.AnalyseMatchingMnemonics(new System.Range(textStart, linePos), false);

                    if (possibleNextState == LineAnalysisState.InvalidMnemonic)
                    {
                        _currentLine.ConditionCodeRange =
                            new Range(_lineIndex, linePos - 1, _lineIndex, linePos + 1);

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
                        this.HandleLabel(linePos, ref textStart);
                        break;
                    }

                    var range = (loadingSpecifierStart + 1)..(linePos + 1);

                    if (!IsValidSymbolChar(c))
                    {
                        var spec = new AnalysedSpecifier(line[range], new Range(_lineIndex, loadingSpecifierStart,
                            _lineIndex, linePos));

                        _currentLine.Specifiers.Add(spec);

                        this.FinishCurrentLine(linePos, LineAnalysisState.SpecifierSyntaxError);
                        return;
                    }

                    _state = this.DetermineSpecifierSyntaxValidity(range);
                }
                    break;
                case LineAnalysisState.InvalidSpecifier:
                case LineAnalysisState.SpecifierSyntaxError:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(linePos, _state);
                        return;
                    }
                    else if (c == ':')
                    {
                        this.HandleLabel(linePos, ref textStart);
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
                        this.HandleLabel(linePos, ref textStart);
                    }

                    // At this state, there's no possibility of finding a new matching mnemonic by consuming more characters
                    // -> we can just stay here until the whole line is terminated
                    // TODO: fast-forward this line to its end (adjust _currentPosition)

                    break;
                case LineAnalysisState.MnemonicLoaded:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(linePos, this.ValidateSoleMnemonic());
                        return;
                    }
                    else if (c == ' ')
                    {
                        // Staying here
                        break;
                    }
                    else
                    {
                        this.AnalyseOperandsAndFinishLine(linePos);
                        return;
                    }
                case LineAnalysisState.InvalidOperands:
                case LineAnalysisState.SyntaxError:
                    //if (c == '\n')
                {
                    this.FinishCurrentLine(linePos, LineAnalysisState.SyntaxError);
                    return;
                }
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

    private void HandleLabel(int linePos, ref int textStart)
    {
        _currentLine!.Mnemonic = null;
        _currentLine.MnemonicRange = null;
        _currentLine.MatchingMnemonics.Clear();
        _currentLine.FullMatches.Clear();

        this.ResetCurrentLineFlags();

        if (!_secondRun)
        {
            var labelStub = new AnalysedLabel(_currentLineText[textStart..linePos], new Range(_lineIndex,
                textStart, _lineIndex, linePos), null);

            _labelsToAppend.Add(labelStub);
        }

        // Label loaded, reset FSM to the start
        textStart = linePos + 1;
        _state = LineAnalysisState.Empty;
    }

    /// <summary>
    /// Sets the current line's state and analysis ending position. Resets the FSM.
    /// </summary>
    /// <param name="linePosition">Index of the character where the analysis has ended.</param>
    /// <param name="endState">The resulting state of the currently analysed line.</param>
    private void FinishCurrentLine(int linePosition, LineAnalysisState endState)
    {
        _currentLine!.PreFinishState = _state;
        _state = LineAnalysisState.Empty;
        _currentLine.State = endState;
        _currentLine.EndCharacter = linePosition;
    }

    /// <summary>
    /// Checks a part of a line 
    /// </summary>
    /// <returns><see cref="LineAnalysisState.InvalidMnemonic"/> (no matches),
    /// <see cref="LineAnalysisState.HasMatches"/> (possible mnemonics but no full match), or
    /// <see cref="LineAnalysisState.HasFullMatch"/> (a valid mnemonic found).</returns>
    private async Task<LineAnalysisState> AnalyseMatchingMnemonics(System.Range consumedRange,
        bool clearMatch = true)
    {
        var linePart = _currentLineText[consumedRange];

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

        var fullMatches = mnemonics.Where(m =>
            m.Mnemonic.Equals(linePart.Trim(), StringComparison.InvariantCultureIgnoreCase)).ToList();

        if (fullMatches.Count > 0)
        {
            _currentLine.FullMatches = fullMatches;
            _currentLine.Mnemonic = fullMatches.FirstOrDefault(f => !_unsuccessfulVariants.Contains(f));
            if (_currentLine.Mnemonic == null)
            {
                return LineAnalysisState.InvalidMnemonic;
            }

            _currentLine.MnemonicRange =
                new Range(_lineIndex, consumedRange.Start.Value, _lineIndex, consumedRange.End.Value);

            return LineAnalysisState.HasFullMatch;
        }

        return LineAnalysisState.HasMatches;
    }

    /// <summary>
    /// Checks if the currently analysed line is valid after it's been terminated only with loaded mnemonic and no operands.
    /// Returns a <see cref="LineAnalysisState"/> to finish the current line with.
    /// </summary>
    /// <returns>The analysis state to end the line with.</returns>
    private LineAnalysisState ValidateSoleMnemonic()
    {
        if (_currentLine?.Mnemonic == null)
        {
            return LineAnalysisState.InvalidMnemonic;
        }

        // Needs operands -> InvalidOperands
        if (_currentLine.Mnemonic.HasOperands && _currentLine.Mnemonic.Operands.Any(o => !o.Optional))
        {
            _currentLine.MissingOperands = true;
            _currentLine.ErroneousOperandIndex = 0;

            return LineAnalysisState.InvalidOperands;
        }

        // Call a validator if it exists, or consider this line valid.
        var validator = _instructionValidatorProvider.For(_currentLine.Mnemonic);
        return validator?.ValidateInstruction(_currentLineText, _currentLine, false) ?? LineAnalysisState.ValidLine;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <returns>LoadingSpecifier, InvalidSpecifier, SpecifierSyntaxError or HasFullMatch.</returns>
    private LineAnalysisState DetermineSpecifierSyntaxValidity(System.Range consumedRange)
    {
        var specifier = _currentLineText[consumedRange];
        var m = _currentLine!.Mnemonic!;
        var specifierIndex = _currentLine.Specifiers.Count;
        var lineRange = new Range(_lineIndex, consumedRange.Start.Value - 1, _lineIndex,
            consumedRange.End.Value);

        if (EnumExtensions.TryParseName(specifier, out InstructionSize instructionSize))
        {
            var allowed = specifierIndex == 0 &&
                          (!m.ForcedSize.HasValue || m.ForcedSize.Value == instructionSize);

            var spec = new AnalysedSpecifier(specifier, lineRange,
                instructionSize, allowed);

            _currentLine.Specifiers.Add(spec);
            return allowed ? LineAnalysisState.HasFullMatch : LineAnalysisState.InvalidSpecifier;
        }

        if (_currentLine.Specifiers.FirstOrDefault()?.IsInstructionSizeQualifier ?? false)
            specifierIndex--;

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

    private struct OperandAnalysisChain
    {
        public int ErroneousOperandIndex { get; set; } = -1;
        public int EndLinePosition { get; set; } = -1;
        public LineAnalysisState EndLineState { get; set; } = LineAnalysisState.InvalidOperands;
        public bool MissingOperands { get; set; }
        public List<AnalysedOperand> Operands { get; } = new();

        public OperandConsumingState ConsumingState { get; set; }

        public OperandAnalysisChain Clone()
        {
            var ret = new OperandAnalysisChain()
            {
                ErroneousOperandIndex = this.ErroneousOperandIndex,
                EndLinePosition = this.EndLinePosition,
                EndLineState = this.EndLineState,
                MissingOperands = this.MissingOperands,
                ConsumingState = this.ConsumingState
            };

            ret.Operands.AddRange(this.Operands);
            return ret;
        }
    }

    /// <summary>
    /// Performs operand analysis on the current line using regular expression matching and recursive descend.
    /// </summary>
    /// <param name="linePos">Index of the first character of the first operand on the line.</param>
    private void AnalyseOperandsAndFinishLine(int linePos)
    {
        var opPart = _currentLineText[linePos..];
        var mnemonic = _currentLine!.Mnemonic!;
        var opDescriptors = mnemonic.Operands;

        // Check case: Instruction with no operands, text in the operands part
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

        // Check case: Instruction with some required operands, no text in the operands part
        // This is probably not necessary because the FSM consumes the space
        if (opDescriptors.Any(o => !o.Optional) && opPart.Trim().Length == 0)
        {
            _currentLine.MissingOperands = true;
            _currentLine.ErroneousOperandIndex = 0;

            this.FinishCurrentLine(linePos, LineAnalysisState.InvalidOperands);
            return;
        }

        var chain = new OperandAnalysisChain();
        var longestMatchedChain = chain;

        for (var descriptorIndex = 0; descriptorIndex < opDescriptors.Count; descriptorIndex++)
        {
            var descriptor = opDescriptors[descriptorIndex];
            var analysisResult = this.ConsumeOperand(opPart, linePos, 0, descriptorIndex, 0, ref chain);

            if (!analysisResult && descriptor.Optional)
            {
                // Analysis was unsuccessful when starting on an optional operand
                // Throw that analysis chain away and try to begin the analysis on the following operand
                if (chain.Operands.Count >= longestMatchedChain.Operands.Count)
                {
                    longestMatchedChain = chain;
                }

                chain = new OperandAnalysisChain() { ConsumingState = OperandConsumingState.ConsumingOperand };
                continue;
            }

            // Whatever the result is, the first operand wasn't optional so we must follow that result
            break;
        }

        if (chain.EndLineState != LineAnalysisState.ValidLine && longestMatchedChain.ErroneousOperandIndex != -1)
        {
            chain = longestMatchedChain;
        }

        // Apply the operand analysis to the current LineAnalysis and finish the line  
        _currentLine.ErroneousOperandIndex = chain.ErroneousOperandIndex;
        _currentLine.MissingOperands = chain.MissingOperands;
        _currentLine.Operands = chain.Operands;

        if (chain.EndLineState == LineAnalysisState.ValidLine)
        {
            var validator = _instructionValidatorProvider.For(_currentLine.Mnemonic!);
            if (validator != null)
            {
                chain.EndLineState = validator.ValidateInstruction(_currentLineText, _currentLine, true);
            }
        }

        this.FinishCurrentLine(chain.EndLinePosition, chain.EndLineState);
    }

    /// <summary>
    /// Describes the state of an operand parsing chain.
    /// </summary>
    private enum OperandConsumingState
    {
        /// Current position is on the start of a possible operand (or end of line).
        ConsumingOperand,

        /// Current position is after a matched operand, there are one or more operand descriptors to consume left.
        ConsumedOperand,

        /// <summary>
        /// Current position is after a matched operand, it was a match of the last available descriptor, so no more
        /// operands can be matched, an end of line must follow.
        /// </summary>
        ConsumedLastOperand
    }

    /// <summary>
    /// Attempts to match a certain type of operand, described by <see cref="OperandDescriptor"/>, on a given position
    /// in a line. If successful, calls itself to match the next operand. This way, an <see cref="OperandAnalysisChain"/>
    /// is created that holds information about the whole analysis process, up to its termination by a valid line, or by
    /// an error.
    /// </summary>
    /// <param name="opPart">A string with only the operand part of the current line.</param>
    /// <param name="opPartLinePos">Index of the first character of the first operand on the line (relative to the original line).</param>
    /// <param name="currentPos">Position to start consuming the operand on (relative to the operand part of the line).
    /// This is the index of a character following the end character of the previous consumed operand.</param>
    /// <param name="descriptorIndex">Index of the <see cref="OperandDescriptor"/> object that the line is being matched against,
    /// in the <see cref="InstructionVariant.Operands"/> list of the current line's <see cref="InstructionVariant"/>.</param>
    /// <param name="actualOperandIndex">Position of the currently analysed operand as used in the source text
    /// (taking skipped optional operands into consideration).</param>
    /// <param name="chain">A temporary storage for the results of this analysis chain.</param>
    /// <returns>True if this operand and all the following ones in the chain were matched successfully.</returns>
    private bool ConsumeOperand(string opPart, int opPartLinePos, int currentPos, int descriptorIndex,
        int actualOperandIndex, ref OperandAnalysisChain chain)
    {
        var mnemonic = _currentLine!.Mnemonic!;
        var opDescriptors = mnemonic.Operands;
        var maxDescriptorIndex = opDescriptors.Count - 1;
        var canHaveMoreOperands = descriptorIndex < maxDescriptorIndex;

        switch (chain.ConsumingState)
        {
            case OperandConsumingState.ConsumingOperand:
            {
                var descriptor = opDescriptors[descriptorIndex];
                var analyser = _operandAnalyserProvider.For(descriptor);

                // <int Regex, Match match> 
                var matches = new List<Match>();
                var total = 0;
                var failed = 0;
                var initPos = currentPos;

                foreach (var regex in descriptor.Regexes)
                {
                    var match = regex.Match(opPart, currentPos);
                    if (!match.Success || match.Index != currentPos)
                    {
                        failed++;
                    }

                    currentPos += match.Length;
                    matches.Add(match);
                    total++;
                }

                if (failed == total) // TODO: is this necessary?
                {
                    var invalidRange = new Range(_lineIndex, opPartLinePos + initPos, _lineIndex,
                        _currentLine.LineLength);
                    var invalidAnalysed = new AnalysedOperand(actualOperandIndex, descriptor, invalidRange,
                        OperandResult.SyntaxError, invalidRange);

                    chain.Operands.Add(invalidAnalysed);
                    chain.ErroneousOperandIndex = invalidAnalysed.Index;
                    chain.EndLinePosition = _currentLine.LineLength;
                    chain.EndLineState = LineAnalysisState.InvalidOperands;

                    return false;
                }

                var range = new Range(_lineIndex, opPartLinePos + initPos, _lineIndex,
                    opPartLinePos + currentPos);

                var analysed = analyser.AnalyseOperand(actualOperandIndex, opPartLinePos, matches, range);
                chain.Operands.Add(analysed);

                if (analysed.Result != OperandResult.Valid)
                {
                    // Invalid operand -> terminate analysis altogether
                    chain.ErroneousOperandIndex = actualOperandIndex;
                    chain.EndLinePosition = range.End.Character;
                    chain.EndLineState = LineAnalysisState.InvalidOperands;

                    return false;
                }

                chain.ConsumingState = canHaveMoreOperands
                    ? OperandConsumingState.ConsumedOperand
                    : OperandConsumingState.ConsumedLastOperand;

                break;
            }
            case OperandConsumingState.ConsumedOperand:
            {
                var commaMatch = _commaRegex.Match(opPart, currentPos);
                if (commaMatch.Success)
                {
                    currentPos += commaMatch.Length;
                    chain.ConsumingState = OperandConsumingState.ConsumingOperand;
                    var longestMatchedChain = chain;

                    for (var nextDescriptorIndex = descriptorIndex;
                         nextDescriptorIndex < opDescriptors.Count;
                         nextDescriptorIndex++)
                    {
                        var chainContinuation = chain.Clone(); // TODO: this is very ineffective

                        var nextDescriptor = opDescriptors[nextDescriptorIndex];
                        var analysisResult = this.ConsumeOperand(opPart, opPartLinePos, currentPos, nextDescriptorIndex,
                            actualOperandIndex, ref chainContinuation);

                        if (!analysisResult && nextDescriptor.Optional) // The chain did not get a good result
                        {
                            if (chainContinuation.Operands.Count >= longestMatchedChain.Operands.Count)
                            {
                                longestMatchedChain = chainContinuation;
                            }

                            continue;
                        }

                        chain = chainContinuation;
                        return analysisResult;
                    }

                    if (chain.EndLineState != LineAnalysisState.ValidLine &&
                        longestMatchedChain.ErroneousOperandIndex != -1)
                    {
                        chain = longestMatchedChain;
                    }

                    return false;
                }

                var isEndLine = _endLineRegex.IsMatch(opPart, currentPos);

                if (isEndLine)
                {
                    var nextOperand = opDescriptors.Skip(descriptorIndex).FirstOrDefault(o => !o.Optional);
                    if (nextOperand == null)
                    {
                        // No required operands follow
                        chain.EndLinePosition = currentPos;
                        chain.EndLineState = LineAnalysisState.ValidLine;
                        return true;
                    }

                    // Missing operand
                    var range = new Range(_lineIndex, opPartLinePos + currentPos, _lineIndex,
                        _currentLine.LineLength);
                    var analysed = new AnalysedOperand(actualOperandIndex, nextOperand, range,
                        OperandResult.MissingOperand, range);

                    chain.Operands.Add(analysed);
                    chain.MissingOperands = true;
                    chain.ErroneousOperandIndex = analysed.Index;
                    chain.EndLinePosition = _currentLine.LineLength;
                    chain.EndLineState = LineAnalysisState.InvalidOperands;

                    return false;
                }

                var lastAnalysed = chain.Operands[^1];
                var newAnalysis = lastAnalysed with
                {
                    Result = OperandResult.SyntaxError,
                    ErrorRange = new Range(_lineIndex, lastAnalysed.Range.End.Character, _lineIndex,
                        _currentLine.LineLength)
                };

                chain.Operands.RemoveAt(chain.Operands.Count - 1);
                chain.Operands.Add(newAnalysis);
                chain.ErroneousOperandIndex = newAnalysis.Index;
                chain.EndLinePosition = _currentLine.LineLength;
                chain.EndLineState = LineAnalysisState.InvalidOperands;

                return false;
            }
            case OperandConsumingState.ConsumedLastOperand:
            {
                var isEndLine = _endLineRegex.IsMatch(opPart, currentPos);
                if (isEndLine)
                {
                    chain.EndLinePosition = currentPos;
                    chain.EndLineState = LineAnalysisState.ValidLine;
                    return true;
                }

                var commaMatch = _commaRegex.Match(opPart, currentPos);
                if (commaMatch.Success)
                {
                    // Unexpected operand
                    var range = new Range(_lineIndex, opPartLinePos + currentPos, _lineIndex,
                        _currentLine.LineLength);
                    var analysed = new AnalysedOperand(actualOperandIndex, null, range,
                        OperandResult.UnexpectedOperand, range);

                    chain.Operands.Add(analysed);
                    chain.ErroneousOperandIndex = analysed.Index;
                    chain.EndLinePosition = _currentLine.LineLength;
                    chain.EndLineState = LineAnalysisState.InvalidOperands;

                    return false;
                }

                // Syntax error
                var lastAnalysed = chain.Operands[^1];
                var newAnalysis = lastAnalysed with
                {
                    Result = OperandResult.SyntaxError,
                    ErrorRange = new Range(_lineIndex, lastAnalysed.Range.End.Character, _lineIndex,
                        _currentLine.LineLength)
                };

                chain.Operands.RemoveAt(chain.Operands.Count - 1);
                chain.Operands.Add(newAnalysis);
                chain.ErroneousOperandIndex = newAnalysis.Index;
                chain.EndLinePosition = _currentLine.LineLength;
                chain.EndLineState = LineAnalysisState.InvalidOperands;
                return false;
            }
            default:
                throw new ArgumentOutOfRangeException();
        }

        return this.ConsumeOperand(opPart, opPartLinePos, currentPos, descriptorIndex + 1, actualOperandIndex + 1,
            ref chain);
    }

    /// <summary>
    /// Resets all flags, <see cref="AnalysedLine.SetFlagsRange"/> and <see cref="AnalysedLine.ConditionCodeRange"/>
    /// on the current analysed line. Used to discard those when the presumption about the mnemonic having a flag
    /// turns out to be invalid when the next character is loaded.
    /// </summary>
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

    /// Characters that may start a condition code.
    private static readonly char[] ConditionCodeStarts =
    {
        'E', 'e', 'N', 'n', 'C', 'c', 'H', 'h', 'L', 'l', 'M', 'm',
        'P', 'p', 'V', 'v', 'G', 'g', 'A', 'a'
    };

    /// <summary>
    /// Checks whether a given character may start a condition code (so the FSM transitions into <see cref="LineAnalysisState.PossibleConditionCode"/>).
    /// </summary>
    private static bool StartsConditionCode(char c) => ConditionCodeStarts.Contains(c);

    private static bool IsValidSymbolChar(char c, bool firstChar = false) =>
        (firstChar ? char.IsLetter(c) : char.IsLetterOrDigit(c)) || c is '_' or '.' or '$';
}
