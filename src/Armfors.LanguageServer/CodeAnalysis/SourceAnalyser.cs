// SourceAnalyser.cs
// Author: Ondřej Ondryáš

using System.Text.RegularExpressions;
using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Models.Abstractions;
using Armfors.LanguageServer.Services.Abstractions;
using Microsoft.Extensions.Logging;
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

    private struct OperandAnalysisChain
    {
        public int ErroneousOperandIndex { get; set; } = -1;
        public int EndLinePosition { get; set; } = -1;
        public LineAnalysisState EndLineState { get; set; } = LineAnalysisState.InvalidOperands;
        public bool MissingOperands { get; set; }
        public List<AnalysedOperand> Operands { get; } = new();

        public OperandAnalysisChain Clone()
        {
            var ret = new OperandAnalysisChain()
            {
                ErroneousOperandIndex = this.ErroneousOperandIndex,
                EndLinePosition = this.EndLinePosition,
                EndLineState = this.EndLineState,
                MissingOperands = this.MissingOperands
            };

            ret.Operands.AddRange(this.Operands);
            return ret;
        }
    }

    /// <summary>
    /// Performs operand analysis of a given line using regular expression matching and recursive descend.
    /// </summary>
    /// <param name="line">The whole line being analysed.</param>
    /// <param name="linePos">Index of the first character of the first operand on the line.</param>
    private void AnalyseOperandsAndFinishLine(string line, int linePos)
    {
        var opPart = line[linePos..];
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
        if (opDescriptors.Any(o => !o.Optional) && opPart.Trim().Length == 0)
        {
            _currentLine.MissingOperands = true;
            _currentLine.ErroneousOperandIndex = 0;

            this.FinishCurrentLine(linePos, LineAnalysisState.InvalidOperands);
            return;
        }

        var chain = new OperandAnalysisChain();

        for (var descriptorIndex = 0; descriptorIndex < opDescriptors.Count; descriptorIndex++)
        {
            var descriptor = opDescriptors[descriptorIndex];
            var analysisResult = this.ConsumeOperand(opPart, linePos, 0, descriptorIndex, descriptor, 0, ref chain);

            if (!analysisResult && descriptor.Optional)
            {
                // Analysis was unsuccessful when starting on an optional operand
                // Throw that analysis chain away and try to begin the analysis on the following operand
                chain = new OperandAnalysisChain();
                continue;
            }

            // Whatever the result is, the first operand wasn't optional so we must follow that result
            break;
        }

        // Apply the operand analysis to the current LineAnalysis and finish the line  
        _currentLine.ErroneousOperandIndex = chain.ErroneousOperandIndex;
        _currentLine.MissingOperands = chain.MissingOperands;
        _currentLine.Operands = chain.Operands;

        this.FinishCurrentLine(chain.EndLinePosition, chain.EndLineState);
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
    /// <param name="descriptor">Reference to the <see cref="OperandDescriptor"/> object that the line is being matched against.</param>
    /// <param name="actualOperandIndex">Position of the currently analysed operand as used in the source text
    /// (taking skipped optional operands into consideration).</param>
    /// <param name="chain">A temporary storage for the results of this analysis chain.</param>
    /// <returns>True if this operand and all the following ones in the chain were matched successfully.</returns>
    private bool ConsumeOperand(string opPart, int opPartLinePos, int currentPos, int descriptorIndex,
        OperandDescriptor descriptor, int actualOperandIndex, ref OperandAnalysisChain chain)
    {
        var mnemonic = _currentLine!.Mnemonic!;
        var opDescriptors = mnemonic.Operands;
        var maxDescriptorIndex = opDescriptors.Count - 1;
        var canHaveMoreOperands = descriptorIndex < maxDescriptorIndex;

        var match = descriptor.Regex.Match(opPart, currentPos);

        if (match.Success && match.Index == currentPos)
        {
            var range = new Range(_lineIndex, opPartLinePos + currentPos, _lineIndex,
                opPartLinePos + currentPos + match.Length);

            var analysed = this.CheckOperand(actualOperandIndex, opPartLinePos, descriptor, match, range);

            chain.Operands.Add(analysed);

            if (analysed.Result != OperandResult.Valid)
            {
                // Invalid operand -> terminate analysis altogether
                chain.ErroneousOperandIndex = actualOperandIndex;
                chain.EndLinePosition = range.End.Character;
                chain.EndLineState = LineAnalysisState.InvalidOperands;

                return false;
            }

            currentPos += match.Length;
        }

        var commaMatch = _commaRegex.Match(opPart, currentPos);
        if (commaMatch.Success)
        {
            currentPos += commaMatch.Length;
        }

        if (_endLineRegex.IsMatch(opPart, currentPos))
        {
            if (commaMatch.Success)
            {
                // End of line after a comma
                // Is the last possible operand -> UnexpectedOperand
                // Otherwise -> SyntaxError

                var range = new Range(_lineIndex, opPartLinePos + currentPos, _lineIndex,
                    _currentLine.LineLength);

                var analysed = new AnalysedOperand(actualOperandIndex + 1, null, range,
                    canHaveMoreOperands ? OperandResult.SyntaxError : OperandResult.UnexpectedOperand,
                    range);

                chain.Operands.Add(analysed);
                chain.ErroneousOperandIndex = actualOperandIndex + 1;
                chain.EndLinePosition = opPartLinePos + currentPos;
                chain.EndLineState = LineAnalysisState.InvalidOperands;

                return false;
            }

            if (canHaveMoreOperands && opDescriptors.Skip(descriptorIndex + 1).Any(o => !o.Optional))
            {
                // End of line after an operand in the middle (there should be more required operands)
                chain.MissingOperands = true;
                chain.ErroneousOperandIndex = actualOperandIndex + 1;
                chain.EndLinePosition = opPartLinePos + currentPos;
                chain.EndLineState = LineAnalysisState.InvalidOperands;

                return false;
            }

            chain.EndLinePosition = _currentLine.LineLength;
            chain.EndLineState = LineAnalysisState.ValidLine;
            return true;
        }

        if (!commaMatch.Success)
        {
            if (match.Success)
            {
                // Neither comma nor EOL -> unexpected characters -> SyntaxError instead of the matched operand
                var lastOp = chain.Operands[^1];
                chain.Operands.RemoveAt(chain.Operands.Count - 1);
                var newOp = lastOp with
                {
                    Result = OperandResult.SyntaxError,
                    ErrorRange = new Range(_lineIndex, lastOp.Range.End.Character, _lineIndex, _currentLine.LineLength)
                };

                chain.Operands.Add(newOp);
                chain.ErroneousOperandIndex = lastOp.Index;
                chain.EndLinePosition = opPartLinePos + currentPos;
                chain.EndLineState = LineAnalysisState.InvalidOperands;

                return false;
            }
            else
            {
                var range = new Range(_lineIndex, opPartLinePos + currentPos, _lineIndex,
                    _currentLine.LineLength);

                var analysed = new AnalysedOperand(actualOperandIndex, descriptor, range, OperandResult.SyntaxError,
                    range);

                chain.Operands.Add(analysed);
                chain.ErroneousOperandIndex = actualOperandIndex;
                chain.EndLinePosition = range.End.Character;
                chain.EndLineState = LineAnalysisState.InvalidOperands;

                return false;
            }
        }

        // Consumed comma and the line doesn't end after the loaded operand
        if (canHaveMoreOperands)
        {
            for (var nextDescriptorIndex = descriptorIndex + 1;
                 nextDescriptorIndex < opDescriptors.Count;
                 nextDescriptorIndex++)
            {
                var chainContinuation = chain.Clone(); // TODO: this is very ineffective

                var nextDescriptor = opDescriptors[nextDescriptorIndex];
                var analysisResult = this.ConsumeOperand(opPart, opPartLinePos, currentPos, nextDescriptorIndex,
                    nextDescriptor, actualOperandIndex + 1, ref chainContinuation);

                if (!analysisResult && nextDescriptor.Optional) // The chain did not get a good result
                    continue;

                chain = chainContinuation;
                return analysisResult;
            }
        }

        var failureRange = new Range(_lineIndex, opPartLinePos + currentPos, _lineIndex,
            _currentLine.LineLength);
        var lastOperand = new AnalysedOperand(actualOperandIndex + 1, null, failureRange, OperandResult.SyntaxError,
            failureRange);

        chain.Operands.Add(lastOperand);
        chain.ErroneousOperandIndex = actualOperandIndex + 1;
        chain.EndLinePosition = failureRange.End.Character;
        chain.EndLineState = LineAnalysisState.InvalidOperands;

        return false;
    }

    private AnalysedOperand CheckOperand(int opIndex, int opPartLinePos, OperandDescriptor descriptor, Match match,
        Range range)
    {
        /*
         TODO:
         - imm checking (standalone, constants, in addressing...)
         - reg name and type checking
         - shift type checking
         - literal checking? guess not, this is covered by the regex itself? or should it be?
         - register list checking
         - alignment checking
        */

        var resultTokens = new List<AnalysedOperandToken>();
        var input = descriptor.IsSingleToken
            ? Enumerable.Repeat(
                new KeyValuePair<int, OperandToken>(descriptor.SingleTokenMatchGroup, descriptor.SingleToken!), 1)
            : descriptor.MatchGroupsTokenMappings ?? Enumerable.Empty<KeyValuePair<int, OperandToken>>();

        var hasErrors = false;
        foreach (var (groupIndex, token) in input)
        {
            if (match.Groups.Count <= groupIndex)
                continue;

            var matchGroup = match.Groups[groupIndex];
            var tokenRange = new Range(range.Start.Line,
                opPartLinePos + matchGroup.Index, range.Start.Line,
                opPartLinePos + matchGroup.Index + matchGroup.Length);

            var aot = this.CheckToken(descriptor, match, token, tokenRange, matchGroup);
            if (aot.Result != OperandTokenResult.Valid && !aot.WarningOnly)
            {
                hasErrors = true;
            }

            resultTokens.Add(aot);
        }

        return new AnalysedOperand(opIndex, descriptor, range,
            hasErrors ? OperandResult.InvalidTokens : OperandResult.Valid, null, resultTokens);
    }

    private AnalysedOperandToken CheckToken(OperandDescriptor descriptor, Match operandMatch,
        OperandToken token, Range tokenRange, Group tokenMatch)
    {
        if (token.Type == OperandTokenType.ImmediateConstant)
        {
            var number = int.Parse(tokenMatch.Value);
            var negative = number < 0;
            if (negative)
            {
                number = -number;
            }

            var valid = CheckModifiedImmediateConstant((uint)number);
            if (!valid)
            {
                return new AnalysedOperandToken(token.Type, OperandTokenResult.InvalidImmediateConstantValue,
                    tokenRange,
                    tokenMatch.Value);
            }
            
            if (negative)
            {
                return new AnalysedOperandToken(token.Type, OperandTokenResult.ImmediateConstantNegative, tokenRange,
                    tokenMatch.Value, true);
            }
        }


        return new AnalysedOperandToken(token.Type, OperandTokenResult.Valid, tokenRange, tokenMatch.Value);
    }

    /// <summary>
    /// Checks whether the specified number is a valid modified immediate constant.
    /// </summary>
    /// <remarks>See the Architecture Reference Manual, chapter F1.7.7.</remarks>
    /// <returns></returns>
    private static bool CheckModifiedImmediateConstant(uint number)
    {
        if (number <= 0xFFu) return true;
        for (var i = 2; i < 32; i += 2)
        {
            // Rotate number (left) and check if it's under 255
            if (((number << i) | (number >> (32 - i))) <= 0xFFu)
            {
                return true;
            }
        }

        return false;
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
