// SourceAnalyser.cs
// Author: Ondřej Ondryáš

using System.Text.RegularExpressions;
using Code4Arm.LanguageServer.CodeAnalysis.Abstractions;
using Code4Arm.LanguageServer.CodeAnalysis.Models;
using Code4Arm.LanguageServer.Extensions;
using Code4Arm.LanguageServer.Models.Abstractions;
using Code4Arm.LanguageServer.Services.Abstractions;
using Microsoft.Extensions.Logging;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.CodeAnalysis;

public class SourceAnalyser : ISourceAnalyser
{
    private readonly ISource _source;
    private readonly IInstructionProvider _instructionProvider;
    private readonly IOperandAnalyserProvider _operandAnalyserProvider;
    private readonly IInstructionValidatorProvider _instructionValidatorProvider;
    private readonly IDiagnosticsPublisher _diagnosticsPublisher;
    private readonly IDirectiveAnalyser _directiveAnalyser;
    private readonly ILogger<SourceAnalyser> _logger;

    private readonly SemaphoreSlim _analysisSemaphore = new(1);

    private Dictionary<int, AnalysedLine>? _lastAnalysisLines;
    private Dictionary<string, AnalysedLabel>? _lastAnalysisLabels;
    private List<AnalysedFunction>? _lastFunctions;

    private AnalysisContext _ctx;

    public ISource Source => _source;

    private int _analysedVersion = -1;

    internal AnalysisContext Context => _ctx;

    internal SourceAnalyser(ISource source, IInstructionProvider instructionProvider,
        IOperandAnalyserProvider operandAnalyserProvider, IInstructionValidatorProvider instructionValidatorProvider,
        IDiagnosticsPublisher diagnosticsPublisher, IDirectiveAnalyser directiveAnalyser,
        ILogger<SourceAnalyser> logger)
    {
        _source = source;
        _instructionProvider = instructionProvider;
        _operandAnalyserProvider = operandAnalyserProvider;
        _instructionValidatorProvider = instructionValidatorProvider;
        _diagnosticsPublisher = diagnosticsPublisher;
        _directiveAnalyser = directiveAnalyser;
        _logger = logger;

        _ctx = null!;
    }

    public async Task TriggerFullAnalysis()
    {
        if (_analysedVersion >= _source.Version)
        {
            _logger.LogTrace("Full analysis request, returning last version {Version}.", _analysedVersion);
            return;
        }

        _logger.LogTrace(
            "Full analysis request. Analysed version: {AnalysedVersion}. Source version: {SourceVersion}.",
            _analysedVersion, _source.Version);

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

            var capacity = _lastAnalysisLines != null
                ? _lastAnalysisLines.Count + (_lastAnalysisLines.Count >> 2)
                : 16;

            _ctx = new AnalysisContext(this, capacity, _lastAnalysisLabels?.Count ?? 4);

            var labelsStart = -1;

            foreach (var line in enumerable)
            {
                _ctx.FirstRunOnCurrentLine = true;
                _ctx.InsideString = false;
                _ctx.State = LineAnalysisState.Empty;
                _ctx.CurrentLineIndex++;

                // TODO: handle line endings in a better way
                _ctx.CurrentLineText = (line.Length == 0 || line[^1] != '\n') ? (line + '\n') : line;

                // Analyse the current line 
                await this.FindBestCurrentLineAnalysis();
                _ctx.AnalysedLines.Add(_ctx.CurrentLineIndex, _ctx.CurrentLine);

                //_logger.LogTrace(
                //    $"[{_ctx.CurrentLineIndex}]: {_ctx.CurrentLine.Mnemonic?.Mnemonic} ({_ctx.CurrentLine.PreFinishState} -> {_ctx.CurrentLine.State})");

                if (labelsStart == -1 && _ctx.CurrentLine.State == LineAnalysisState.Blank &&
                    _ctx.StubLabels.Count > 0)
                {
                    // Labels were found on the current line and it is otherwise 
                    _logger.LogTrace("Series of labels starting at [{Index}].", _ctx.CurrentLineIndex);
                    labelsStart = _ctx.CurrentLineIndex;
                }
                else if (_ctx.CurrentLine.State != LineAnalysisState.Blank && _ctx.StubLabels.Count > 0)
                {
                    _logger.LogTrace("Series of labels terminating at [{Index}].", _ctx.CurrentLineIndex);
                    this.FixupLineLabels(labelsStart);
                    labelsStart = -1;
                }

                if (_ctx.CurrentLine.Directive is {Type: DirectiveType.Type})
                {
                    var directive = _ctx.CurrentLine.Directive;
                    var match = _funcTypeRegex.Match(directive.ParametersText);

                    if (match.Success)
                    {
                        var targetLabel = match.Groups[1].Value;
                        _ctx.StubFunctions ??= new List<AnalysedFunction>();
                        _ctx.StubFunctions.Add(new AnalysedFunction(targetLabel, directive));
                    }
                }
                else if (_ctx.CurrentLine.Directive is {Type: DirectiveType.Global})
                {
                    var label = _ctx.CurrentLine.Directive.ParametersText;
                    _ctx.GlobalLabels ??= new List<string>();
                    _ctx.GlobalLabels.Add(label);
                }
            }

            this.FillReferencesInLabelOperands();
            this.MarkGlobalLabels();
            this.FindFunctions();

            _analysedVersion = _source.Version ?? -1;
            _lastAnalysisLines = _ctx.AnalysedLines;
            _lastAnalysisLabels = _ctx.AnalysedLabels;
            _lastFunctions = _ctx.StubFunctions;

            _logger.LogDebug(
                "Analysis done. {Lines} lines, {Labels} labels ({Global} global), {Funcs} functions. Analysed version: {AnalysedVersion}.",
                _ctx.AnalysedLines.Count, _ctx.AnalysedLabels.Count, _ctx.GlobalLabels?.Count ?? 0,
                _ctx.StubFunctions?.Count ?? 0, _analysedVersion);
        }
        finally
        {
            _analysisSemaphore.Release();
            _logger.LogTrace("Lock released.");
        }

        await _diagnosticsPublisher.PublishAnalysisResult(this, _source.Uri, _analysedVersion).ConfigureAwait(false);
    }

    private void MarkGlobalLabels()
    {
        if (_ctx.GlobalLabels == null)
            return;

        foreach (var globalLabel in _ctx.GlobalLabels)
        {
            if (_ctx.AnalysedLabels.TryGetValue(globalLabel, out var labelAnalysis))
            {
                labelAnalysis.IsGlobal = true;
            }
        }
    }

    private async Task FindBestCurrentLineAnalysis()
    {
        _unsuccessfulVariants.Clear();

        await this.AnalyseCurrentLine();
        var bestAttempt = _ctx.CurrentLine;

        while (_ctx.CurrentLine.State != LineAnalysisState.ValidLine
               && _ctx.CurrentLine.FullMatches.Count > 1
               && _ctx.CurrentLine.FullMatches.Count > _unsuccessfulVariants.Count)
        {
            if (_ctx.CurrentLine.Mnemonic != null)
            {
                _unsuccessfulVariants.Add(_ctx.CurrentLine.Mnemonic);
            }

            if (bestAttempt.Operands?.Count <= _ctx.CurrentLine.Operands?.Count)
            {
                bestAttempt = _ctx.CurrentLine;
            }

            _ctx.FirstRunOnCurrentLine = false;
            await this.AnalyseCurrentLine();
        }

        if (_ctx.CurrentLine.State != LineAnalysisState.ValidLine)
        {
            _ctx.CurrentLine = bestAttempt;
        }
    }

    private readonly Regex _funcTypeRegex =
        new Regex("^ ?(\\\"[a-zA-Z_.$][a-zA-Z0-9_.$ ]*\\\"|[a-zA-Z_.$][a-zA-Z0-9_.$]*) ?, ?%function ?$",
            RegexOptions.Compiled);

    private void FindFunctions()
    {
        if (_ctx.StubFunctions == null)
            return;

        var beginLines = new List<AnalysedFunction>();
        var startedFunctions = new List<AnalysedFunction>();

        foreach (var stubFunction in _ctx.StubFunctions)
        {
            if (_ctx.AnalysedLabels.TryGetValue(stubFunction.Label, out var label))
            {
                stubFunction.TargetAnalysedLabel = label;
                stubFunction.StartLine = label.PointsTo?.LineIndex ?? label.DefinedAtLine;
                label.TargetFunction = stubFunction;

                if (!beginLines.Contains(stubFunction))
                    beginLines.Add(stubFunction);
            }
        }

        beginLines.Sort((a, b) => a.StartLine - b.StartLine);

        foreach (var pair in _ctx.AnalysedLines)
        {
            if (beginLines.Count > 0)
            {
                var first = beginLines[0];
                while (first.StartLine == pair.Key)
                {
                    startedFunctions.Add(first);
                    beginLines.RemoveAt(0);
                    if (beginLines.Count > 0)
                        first = beginLines[0];
                    else break;
                }
            }

            if (startedFunctions.Count > 0)
            {
                var analysedLine = pair.Value;
                if (EndsFunction(analysedLine))
                {
                    foreach (var function in startedFunctions)
                    {
                        function.EndLine = analysedLine.LineIndex;
                    }

                    startedFunctions.Clear();
                }
            }

            if (beginLines.Count == 0 && startedFunctions.Count == 0)
                break;
        }
    }

    private static bool EndsFunction(AnalysedLine line)
        => (line.Mnemonic?.Mnemonic is "B" or "BX" &&
            (line.Operands?.Any(o => o.Tokens?.Any(t => t.Data.Register == Register.LR) ?? false) ?? false))
           || (line.Mnemonic?.Mnemonic is "POP" or "LDM" or "LDR" &&
               (line.Operands?.Any(o => o.Tokens?.Any(t => t.Data.Register == Register.PC) ?? false) ?? false));

    private void FixupLineLabels(int labelsStart)
    {
        foreach (var label in _ctx.StubLabels)
        {
            var isAlreadyDefined = _ctx.AnalysedLabels.TryGetValue(label.Label, out var alreadyDefined);

            var populatedLabel = label with
            {
                PointsTo = _ctx.CurrentLine,
                Redefines = isAlreadyDefined ? alreadyDefined : null
            };

            _ctx.CurrentLine.Labels.Add(populatedLabel);

            if (!isAlreadyDefined || alreadyDefined!.CanBeRedefined)
            {
                _ctx.AnalysedLabels[label.Label] = label;
            }

            if (labelsStart != -1)
            {
                for (var i = labelsStart; i < _ctx.CurrentLineIndex; i++)
                {
                    _ctx.AnalysedLines[i].Labels.Add(populatedLabel);
                }
            }
        }

        _ctx.StubLabels.Clear();
    }

    private void FillReferencesInLabelOperands()
    {
        var allLabels = _ctx.AnalysedLines.Values
            .Where(o => o.State == LineAnalysisState.ValidLine && o.Operands is {Count: > 0})
            .SelectMany(o => o.Operands!)
            .Where(op => op.Result == OperandResult.Valid && op.Tokens is {Count: > 0})
            .SelectMany(o => o.Tokens!)
            .Where(t => t.Type == OperandTokenType.Label);

        foreach (var labelToken in allLabels)
        {
            if (_ctx.AnalysedLabels.TryGetValue(labelToken.Text, out var targetLabel))
            {
                labelToken.Data = targetLabel;
                targetLabel.ReferencesCount++;
            }
            else
            {
                labelToken.Result = OperandTokenResult.UndefinedLabel;
                labelToken.Severity = DiagnosticSeverity.Information;
            }
        }
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
        return _lastAnalysisLines?[line];
    }

    public IEnumerable<AnalysedLine> GetLineAnalyses()
    {
        return _lastAnalysisLines?.OrderBy(c => c.Key).Select(c => c.Value)
               ?? Enumerable.Empty<AnalysedLine>();
    }

    public IEnumerable<AnalysedLabel> GetLabels()
    {
        return _lastAnalysisLabels?.Values ?? Enumerable.Empty<AnalysedLabel>();
    }

    public AnalysedTokenLookupResult? FindTokenAtPosition(Position position)
    {
        if (_lastAnalysisLines == null)
            return null;
        if (!_lastAnalysisLines.TryGetValue(position.Line, out var lineAnalysis))
            return null;

        foreach (var label in lineAnalysis.Labels)
        {
            if (label.DefinedAtLine == position.Line && label.Range.Contains(position))
            {
                return new AnalysedTokenLookupResult(lineAnalysis, label);
            }
        }

        // TODO: directives!

        var mnemonic = lineAnalysis.Mnemonic;
        if (mnemonic == null)
            // Blank line
            return new AnalysedTokenLookupResult(lineAnalysis, lineAnalysis.AnalysedRange);

        if (lineAnalysis.SetFlagsRange?.Contains(position) ?? false)
            return new AnalysedTokenLookupResult(lineAnalysis, AnalysedTokenType.SetFlagsFlag);

        if (lineAnalysis.ConditionCodeRange?.Contains(position) ?? false)
            return new AnalysedTokenLookupResult(lineAnalysis, AnalysedTokenType.ConditionCode);

        if (lineAnalysis.MnemonicRange!.Contains(position))
            return new AnalysedTokenLookupResult(lineAnalysis, AnalysedTokenType.Mnemonic);

        if (lineAnalysis.HasSpecifiers)
        {
            foreach (var specifier in lineAnalysis.Specifiers)
            {
                if (specifier.Range.Contains(position))
                    return new AnalysedTokenLookupResult(lineAnalysis, specifier);
            }
        }

        if (!mnemonic.HasOperands || lineAnalysis.Operands == null)
            return new AnalysedTokenLookupResult(lineAnalysis, new Range()); // TODO: whitespace at the end?

        AnalysedOperand? cursorIn = null;
        foreach (var analysedOperand in lineAnalysis.Operands)
        {
            if (analysedOperand.Range.Contains(position))
            {
                cursorIn = analysedOperand;
                break;
            }
        }

        if (cursorIn != null)
        {
            if (cursorIn.Descriptor == null || cursorIn.Tokens is null or {Count: 0})
                return new AnalysedTokenLookupResult(lineAnalysis, cursorIn);

            foreach (var token in cursorIn.Tokens)
            {
                if (token.Range.Contains(position))
                {
                    return new AnalysedTokenLookupResult(lineAnalysis, cursorIn, token);
                }
            }

            return new AnalysedTokenLookupResult(lineAnalysis, cursorIn);
        }

        return new AnalysedTokenLookupResult(lineAnalysis,
            new Range(position.Line, position.Character, position.Line,
                position.Character)); // TODO: whitespace in the middle
    }

    public AnalysedLabel? GetLabel(string name)
    {
        return (_lastAnalysisLabels?.TryGetValue(name, out var val) ?? false) ? val : null;
    }

    public IEnumerable<AnalysedTokenLookupResult> FindLabelOccurrences(string label, bool includeDefinition)
    {
        if (_lastAnalysisLines == null)
            yield break;

        foreach (var line in _lastAnalysisLines.Values)
        {
            foreach (var analysedLabel in line.Labels)
            {
                if (analysedLabel.Label == label && analysedLabel.DefinedAtLine == line.LineIndex &&
                    (includeDefinition || analysedLabel.Redefines != null))
                    yield return new AnalysedTokenLookupResult(line, analysedLabel);
            }

            if (line.Operands is null or {Count: 0})
                continue;

            foreach (var operand in line.Operands)
            {
                if (operand.Tokens is null or {Count: 0})
                    continue;

                foreach (var token in operand.Tokens.Where(t => t.Type == OperandTokenType.Label))
                {
                    if (token.Data.TargetLabel != null && token.Data.TargetLabel.Label == label)
                    {
                        yield return new AnalysedTokenLookupResult(line, operand, token);
                    }
                }
            }
        }
    }

    public IEnumerable<AnalysedTokenLookupResult> FindRegisterOccurrences(Register register)
    {
        if (!register.IsSingleRegister())
            throw new InvalidOperationException("Occurrences may only be found for a single register.");

        if (_lastAnalysisLines == null)
            yield break;

        foreach (var line in _lastAnalysisLines.Values)
        {
            if (line.Operands is null or {Count: 0})
                continue;

            foreach (var operand in line.Operands)
            {
                if (operand.Tokens is null or {Count: 0})
                    continue;

                foreach (var token in operand.Tokens.Where(t => t.Type == OperandTokenType.Register))
                {
                    if (token.Data.Register == register)
                    {
                        yield return new AnalysedTokenLookupResult(line, operand, token);
                    }
                }
            }
        }
    }

    public IEnumerable<AnalysedFunction> GetFunctions()
    {
        return _lastFunctions ?? Enumerable.Empty<AnalysedFunction>();
    }

    private List<InstructionVariant> _unsuccessfulVariants = new();

    private async Task AnalyseCurrentLine()
    {
        var line = _ctx.CurrentLineText;
        var loadingSpecifierStart = -1;
        var textStart = 0;

        _ctx.CurrentLine = new AnalysedLine(_ctx.CurrentLineIndex, line.Length);
        _ctx.InsideString = false;

        _logger.LogTrace("Analysing line {Index}.", _ctx.CurrentLineIndex);

        for (var linePos = 0; linePos < line.Length; linePos++)
        {
            var consumedPart = new System.Range(textStart, linePos + 1);

            var c = line[linePos];
            switch (_ctx.State)
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
                    else if (c == '"')
                    {
                        if (_ctx.InsideString)
                        {
                            this.FinishCurrentLine(linePos, LineAnalysisState.SyntaxError);
                        }
                        else
                        {
                            _ctx.InsideString = true;
                        }
                    }
                    else if (!IsValidSymbolChar(c, true))
                    {
                        this.FinishCurrentLine(linePos, LineAnalysisState.SyntaxError);
                        return;
                    }
                    else if (c == '.')
                    {
                        textStart = linePos;
                        _ctx.CurrentLine.StartCharacter = linePos;

                        if (this.HandleDirective(ref linePos, ref textStart))
                            return;
                    }
                    else
                    {
                        // First character loaded, begin mnemonic analysis
                        textStart = linePos;
                        consumedPart = new System.Range(textStart, linePos + 1);
                        _ctx.CurrentLine.StartCharacter = linePos;
                        _ctx.State = await this.AnalyseMatchingMnemonics(consumedPart);
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
                        _ctx.State = LineAnalysisState.SyntaxError;
                    }
                    else
                    {
                        // Analyse further
                        _ctx.State = await this.AnalyseMatchingMnemonics(consumedPart);
                    }

                    break;
                case LineAnalysisState.HasFullMatch:
                    // _ctx.CurrentLine.Mnemonic has been populated by the previous run of AnalyseMatchingMnemonics 
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(linePos, this.ValidateSoleMnemonic());
                        return;
                    }
                    else if (c == ':')
                    {
                        this.HandleLabel(linePos, ref textStart);
                    }
                    else if (c is 'S' or 's' && !_ctx.CurrentLine.HasConditionCodePart &&
                             !_ctx.CurrentLine.HasSpecifiers)
                    {
                        var mnemonic = _ctx.CurrentLine.Mnemonic!;
                        if (mnemonic.HasSetFlagsVariant)
                        {
                            if (_ctx.CurrentLine.SetsFlags)
                            {
                                // E.g. there's an S-able XYZS and a different mnemonic XYZSS
                                _ctx.CurrentLine.SetsFlags = false;
                                _ctx.CurrentLine.SetFlagsRange = null;
                                _ctx.CurrentLine.CannotSetFlags = false;

                                _ctx.State = await this.AnalyseMatchingMnemonics(consumedPart);

                                break;
                            }

                            _ctx.CurrentLine.SetsFlags = true;
                            _ctx.CurrentLine.SetFlagsRange = new Range(_ctx.CurrentLineIndex, linePos,
                                _ctx.CurrentLineIndex,
                                linePos + 1);
                            _ctx.CurrentLine.CannotSetFlags = false;
                        }
                        else
                        {
                            // E.g. there's non-S-able XYZ and a different mnemonic XYZSW
                            _ctx.State = await this.AnalyseMatchingMnemonics(consumedPart, false);

                            if (_ctx.State == LineAnalysisState.InvalidMnemonic)
                            {
                                // This seems to be an attempt to -S a non-S-able instruction
                                // Set the position of the S to signalise to the user
                                _ctx.CurrentLine.SetsFlags = false;
                                _ctx.CurrentLine.SetFlagsRange = new Range(_ctx.CurrentLineIndex, linePos,
                                    _ctx.CurrentLineIndex,
                                    linePos + 1);
                                _ctx.CurrentLine.CannotSetFlags = true;
                            }
                            else
                            {
                                this.ResetCurrentLineFlags();
                            }
                        }
                    }
                    else if (StartsConditionCode(c) && !_ctx.CurrentLine.HasConditionCodePart &&
                             !_ctx.CurrentLine.HasSpecifiers)
                    {
                        var mnemonic = _ctx.CurrentLine.Mnemonic!;
                        if (mnemonic.CanBeConditional)
                        {
                            _ctx.State = LineAnalysisState.PossibleConditionCode;
                        }
                        else
                        {
                            // Check if there isn't a matching instruction (XYZ + E when there are XYZ and XYZE would get us here) 
                            var possibleNextState = await this.AnalyseMatchingMnemonics(consumedPart, false);

                            if (possibleNextState == LineAnalysisState.InvalidMnemonic)
                            {
                                // This seems to be an attempt to add condition code to an unconditional instruction
                                // Set a flag and pretend it's ok to jump into PossibleConditionCode

                                _ctx.CurrentLine.ConditionCodeRange = new Range(_ctx.CurrentLineIndex, linePos,
                                    _ctx.CurrentLineIndex,
                                    linePos + 1);
                                _ctx.CurrentLine.CannotBeConditional = true;
                                _ctx.State = LineAnalysisState.PossibleConditionCode;

                                break;
                            }

                            this.ResetCurrentLineFlags();
                            _ctx.State = possibleNextState;
                        }
                    }
                    else if (c == '.')
                    {
                        // Vector (preferred) or qualifier (.W/.N)
                        _ctx.State = LineAnalysisState.LoadingSpecifier;
                        loadingSpecifierStart = linePos;
                    }
                    else if (c == ' ')
                    {
                        _ctx.CurrentLine.MnemonicFinished = true;
                        _ctx.State = LineAnalysisState.MnemonicLoaded;
                    }
                    else if (!IsValidSymbolChar(c))
                    {
                        _ctx.State = LineAnalysisState.SyntaxError;
                    }
                    else
                    {
                        _ctx.State = await this.AnalyseMatchingMnemonics(consumedPart);
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
                        if (!_ctx.CurrentLine.CannotBeConditional)
                        {
                            _ctx.CurrentLine.ConditionCode = cc;
                        }

                        _ctx.CurrentLine.ConditionCodeRange =
                            new Range(_ctx.CurrentLineIndex, linePos - 1, _ctx.CurrentLineIndex, linePos + 1);

                        _ctx.CurrentLine.HasInvalidConditionCode = false;
                        _ctx.CurrentLine.HasUnterminatedConditionCode = false;

                        _ctx.State = LineAnalysisState.HasFullMatch;
                        break;
                    }

                    _ctx.CurrentLine.ConditionCode = null;

                    // There might still be other valid instructions.
                    var possibleNextState =
                        await this.AnalyseMatchingMnemonics(new System.Range(textStart, linePos), false);

                    if (possibleNextState == LineAnalysisState.InvalidMnemonic)
                    {
                        _ctx.CurrentLine.ConditionCodeRange =
                            new Range(_ctx.CurrentLineIndex, linePos - 1, _ctx.CurrentLineIndex, linePos + 1);

                        if (c is '\n' or ' ')
                        {
                            _ctx.CurrentLine.HasUnterminatedConditionCode = true;

                            // Move one char back to handle mnemonic termination properly in HasFullMatch in the next iteration
                            linePos--;
                        }
                        else
                        {
                            _ctx.CurrentLine.HasInvalidConditionCode = true;
                        }

                        // Pretend everything's OK
                        _ctx.State = LineAnalysisState.HasFullMatch;

                        break;
                    }

                    // There's another valid instruction
                    this.ResetCurrentLineFlags();
                    _ctx.State = possibleNextState;
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
                        var spec = new AnalysedSpecifier(line[range], new Range(_ctx.CurrentLineIndex,
                            loadingSpecifierStart,
                            _ctx.CurrentLineIndex, linePos));

                        _ctx.CurrentLine.Specifiers.Add(spec);

                        this.FinishCurrentLine(linePos, LineAnalysisState.SpecifierSyntaxError);
                        return;
                    }

                    _ctx.State = this.DetermineSpecifierSyntaxValidity(range);
                }
                    break;
                case LineAnalysisState.InvalidSpecifier:
                case LineAnalysisState.SpecifierSyntaxError:
                    if (c == '\n')
                    {
                        this.FinishCurrentLine(linePos, _ctx.State);
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
                    // but there can be a label
                    // -> we can just stay here until the whole line is terminated
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
                    throw new InvalidOperationException($"FSM state cannot be {_ctx.State.ToString()}");
                default:
                    throw new InvalidOperationException($"Invalid FSM state value: {_ctx.State}.");
            }
        }

        if (_ctx.CurrentLine.State == LineAnalysisState.Empty && line.EndsWith('\n'))
        {
            this.FinishCurrentLine(line.Length - 1, _ctx.State);
        }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="linePos"></param>
    /// <param name="textStart"></param>
    /// <returns>True if a directive was parsed; false if it turned out to be a label.</returns>
    private bool HandleDirective(ref int linePos, ref int textStart)
    {
        var lineChunk = _ctx.CurrentLineText[linePos..];
        var labelTerminatorIndex = lineChunk.IndexOf(':');

        if (labelTerminatorIndex != -1)
        {
            this.HandleLabel(labelTerminatorIndex, ref textStart);
            return false;
        }

        var analysis = _directiveAnalyser.AnalyseDirective(lineChunk, linePos, this);
        _ctx.CurrentLine.Directive = analysis;

        this.FinishCurrentLine(_ctx.CurrentLineText.Length,
            (analysis.State == DirectiveState.Valid || analysis.Severity != DiagnosticSeverity.Error)
                ? LineAnalysisState.Directive
                : LineAnalysisState.InvalidDirective);

        return true;
    }

    private void HandleLabel(int linePos, ref int textStart)
    {
        _ctx.CurrentLine.Mnemonic = null;
        _ctx.CurrentLine.MnemonicRange = null;
        _ctx.CurrentLine.MatchingMnemonics.Clear();
        _ctx.CurrentLine.FullMatches.Clear();

        this.ResetCurrentLineFlags();

        if (_ctx.CurrentLineText[linePos - 1] == '"')
        {
            if (_ctx.InsideString)
            {
                linePos--;
            }
            else
            {
                _ctx.State = LineAnalysisState.SyntaxError;
                return;
            }
        }

        var text = _ctx.CurrentLineText[textStart..linePos];
        if (text.Contains(' ') && !_ctx.InsideString)
        {
            _ctx.State = LineAnalysisState.SyntaxError;
            return;
        }

        if (_ctx.FirstRunOnCurrentLine)
        {
            var labelStub = new AnalysedLabel(text, new Range(_ctx.CurrentLineIndex,
                textStart, _ctx.CurrentLineIndex, linePos), null, _ctx.CurrentLineIndex);

            _ctx.StubLabels.Add(labelStub);
        }

        if (_ctx.InsideString)
        {
            _ctx.InsideString = false;
            linePos++;
        }

        // Label loaded, reset FSM to the start
        textStart = linePos + 1;
        _ctx.State = LineAnalysisState.Empty;
    }

    /// <summary>
    /// Sets the current line's state and analysis ending position. Resets the FSM.
    /// </summary>
    /// <param name="linePosition">Index of the character where the analysis has ended.</param>
    /// <param name="endState">The resulting state of the currently analysed line.</param>
    private void FinishCurrentLine(int linePosition, LineAnalysisState endState)
    {
        _ctx.CurrentLine.PreFinishState = _ctx.State;
        _ctx.State = LineAnalysisState.Empty;
        _ctx.CurrentLine.State = endState;
        _ctx.CurrentLine.EndCharacter = linePosition;
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
        var linePart = _ctx.CurrentLineText[consumedRange];

        var mnemonics = await _instructionProvider.FindMatchingInstructions(linePart);
        _ctx.CurrentLine.MatchingMnemonics = mnemonics;

        if (mnemonics.Count == 0)
        {
            if (clearMatch)
            {
                _ctx.CurrentLine.Mnemonic = null;
                _ctx.CurrentLine.MnemonicRange = null;
            }

            return LineAnalysisState.InvalidMnemonic;
        }

        var fullMatches = mnemonics.Where(m =>
            m.Mnemonic.Equals(linePart.Trim(), StringComparison.InvariantCultureIgnoreCase)).ToList();

        if (fullMatches.Count > 0)
        {
            _ctx.CurrentLine.FullMatches = fullMatches;
            _ctx.CurrentLine.Mnemonic = fullMatches.FirstOrDefault(f => !_unsuccessfulVariants.Contains(f));
            if (_ctx.CurrentLine.Mnemonic == null)
            {
                return LineAnalysisState.InvalidMnemonic;
            }

            _ctx.CurrentLine.MnemonicRange =
                new Range(_ctx.CurrentLineIndex, consumedRange.Start.Value, _ctx.CurrentLineIndex,
                    consumedRange.End.Value);

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
        if (_ctx.CurrentLine.Mnemonic == null)
        {
            return LineAnalysisState.InvalidMnemonic;
        }

        // Needs operands -> InvalidOperands
        if (_ctx.CurrentLine.Mnemonic.HasOperands && _ctx.CurrentLine.Mnemonic.Operands.Any(o => !o.Optional))
        {
            _ctx.CurrentLine.MissingOperands = true;
            _ctx.CurrentLine.ErroneousOperandIndex = 0;

            return LineAnalysisState.InvalidOperands;
        }

        // Call a validator if it exists, or consider this line valid.
        var validator = _instructionValidatorProvider.For(_ctx.CurrentLine.Mnemonic);
        return validator?.ValidateInstruction(_ctx.CurrentLineText, _ctx.CurrentLine, false) ??
               LineAnalysisState.ValidLine;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <returns>LoadingSpecifier, InvalidSpecifier, SpecifierSyntaxError or HasFullMatch.</returns>
    private LineAnalysisState DetermineSpecifierSyntaxValidity(System.Range consumedRange)
    {
        var specifier = _ctx.CurrentLineText[consumedRange];
        var m = _ctx.CurrentLine.Mnemonic!;
        var specifierIndex = _ctx.CurrentLine.Specifiers.Count;
        var lineRange = new Range(_ctx.CurrentLineIndex, consumedRange.Start.Value - 1, _ctx.CurrentLineIndex,
            consumedRange.End.Value);

        if (EnumExtensions.TryParseName(specifier, out InstructionSize instructionSize))
        {
            var allowed = specifierIndex == 0 &&
                          (!m.ForcedSize.HasValue || m.ForcedSize.Value == instructionSize);

            var spec = new AnalysedSpecifier(specifier, lineRange,
                instructionSize, allowed);

            _ctx.CurrentLine.Specifiers.Add(spec);
            return allowed ? LineAnalysisState.HasFullMatch : LineAnalysisState.InvalidSpecifier;
        }

        if (_ctx.CurrentLine.Specifiers.FirstOrDefault()?.IsInstructionSizeQualifier ?? false)
            specifierIndex--;

        var vector = VectorDataTypeExtensions.GetVectorDataType(specifier);
        var instructionValidator = _instructionValidatorProvider.For(_ctx.CurrentLine.Mnemonic!);

        if (vector != VectorDataType.Unknown)
        {
            var allowed = instructionValidator != null &&
                          instructionValidator.IsVectorDataTypeAllowed(specifierIndex, vector, _ctx.CurrentLine);
            var spec = new AnalysedSpecifier(specifier, lineRange, vector, specifierIndex, allowed);

            _ctx.CurrentLine.Specifiers.Add(spec);
            return allowed ? LineAnalysisState.HasFullMatch : LineAnalysisState.InvalidSpecifier;
        }

        if (instructionValidator != null)
        {
            var possibleVectorTypes = instructionValidator.GetPossibleVectorDataTypes(specifierIndex, _ctx.CurrentLine);
            if (possibleVectorTypes.Any(possibleVectorType => possibleVectorType.GetTextForm()
                    .StartsWith(specifier, StringComparison.InvariantCultureIgnoreCase)))
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

                _ctx.CurrentLine.Specifiers.Add(spec);
                return LineAnalysisState.InvalidSpecifier;
            }

            if (textForm.StartsWith(specifier, StringComparison.InvariantCultureIgnoreCase))
            {
                return LineAnalysisState.LoadingSpecifier;
            }
        }

        _ctx.CurrentLine.Specifiers.Add(new AnalysedSpecifier(specifier, lineRange));
        return LineAnalysisState.SpecifierSyntaxError;
    }

    private readonly Regex _commaRegex = new("\\G ?, ?", RegexOptions.Compiled);
    private readonly Regex _endLineRegex = new("\\G ?$", RegexOptions.Compiled | RegexOptions.Multiline);

    private struct OperandAnalysisChain
    {
        public OperandAnalysisChain()
        {
        }

        public int ErroneousOperandIndex { get; set; } = -1;
        public int EndLinePosition { get; set; } = -1;
        public LineAnalysisState EndLineState { get; set; } = LineAnalysisState.InvalidOperands;
        public bool MissingOperands { get; set; } = false;
        public List<AnalysedOperand> Operands { get; } = new();

        public OperandConsumingState ConsumingState { get; set; } = OperandConsumingState.ConsumingOperand;

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
        var opPart = _ctx.CurrentLineText[linePos..];
        var mnemonic = _ctx.CurrentLine.Mnemonic!;
        var opDescriptors = mnemonic.Operands;

        // Check case: Instruction with no operands, text in the operands part
        if (opDescriptors.IsEmpty)
        {
            if (opPart.Trim().Length != 0)
            {
                _ctx.CurrentLine.NoOperandsAllowed = true;
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
            _ctx.CurrentLine.MissingOperands = true;
            _ctx.CurrentLine.ErroneousOperandIndex = 0;

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

                chain = new OperandAnalysisChain() {ConsumingState = OperandConsumingState.ConsumingOperand};
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
        _ctx.CurrentLine.ErroneousOperandIndex = chain.ErroneousOperandIndex;
        _ctx.CurrentLine.MissingOperands = chain.MissingOperands;
        _ctx.CurrentLine.Operands = chain.Operands;

        if (chain.EndLineState == LineAnalysisState.ValidLine)
        {
            var validator = _instructionValidatorProvider.For(_ctx.CurrentLine.Mnemonic!);
            if (validator != null)
            {
                chain.EndLineState = validator.ValidateInstruction(_ctx.CurrentLineText, _ctx.CurrentLine, true);
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
        var mnemonic = _ctx.CurrentLine.Mnemonic!;
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

                        var commaMatch = _commaRegex.Match(opPart, currentPos);
                        if (commaMatch.Success)
                        {
                            currentPos += commaMatch.Length;
                        }
                    }

                    if (currentPos == initPos || match.Index != 0) 
                    {
                        currentPos = match.Index + match.Length;
                    }

                    matches.Add(match);
                    total++;
                }

                var range = new Range(_ctx.CurrentLineIndex, opPartLinePos + initPos, _ctx.CurrentLineIndex,
                    opPartLinePos + currentPos);

                var analysed = analyser.AnalyseOperand(actualOperandIndex, opPartLinePos, matches, range, opPart);
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
                    var range = new Range(_ctx.CurrentLineIndex, opPartLinePos + currentPos, _ctx.CurrentLineIndex,
                        _ctx.CurrentLine.LineLength);
                    var analysed = new AnalysedOperand(actualOperandIndex, nextOperand, range,
                        OperandResult.MissingOperand, range);

                    chain.Operands.Add(analysed);
                    chain.MissingOperands = true;
                    chain.ErroneousOperandIndex = analysed.Index;
                    chain.EndLinePosition = _ctx.CurrentLine.LineLength;
                    chain.EndLineState = LineAnalysisState.InvalidOperands;

                    return false;
                }

                var lastAnalysed = chain.Operands[^1];
                var newAnalysis = lastAnalysed with
                {
                    Result = OperandResult.SyntaxError,
                    ErrorRange = new Range(_ctx.CurrentLineIndex, lastAnalysed.Range.End.Character,
                        _ctx.CurrentLineIndex,
                        _ctx.CurrentLine.LineLength)
                };

                chain.Operands.RemoveAt(chain.Operands.Count - 1);
                chain.Operands.Add(newAnalysis);
                chain.ErroneousOperandIndex = newAnalysis.Index;
                chain.EndLinePosition = _ctx.CurrentLine.LineLength;
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
                    var range = new Range(_ctx.CurrentLineIndex, opPartLinePos + currentPos, _ctx.CurrentLineIndex,
                        _ctx.CurrentLine.LineLength);
                    var analysed = new AnalysedOperand(actualOperandIndex, null, range,
                        OperandResult.UnexpectedOperand, range);

                    chain.Operands.Add(analysed);
                    chain.ErroneousOperandIndex = analysed.Index;
                    chain.EndLinePosition = _ctx.CurrentLine.LineLength;
                    chain.EndLineState = LineAnalysisState.InvalidOperands;

                    return false;
                }

                // Syntax error
                var lastAnalysed = chain.Operands[^1];
                var newAnalysis = lastAnalysed with
                {
                    Result = OperandResult.SyntaxError,
                    ErrorRange = new Range(_ctx.CurrentLineIndex, lastAnalysed.Range.End.Character,
                        _ctx.CurrentLineIndex,
                        _ctx.CurrentLine.LineLength)
                };

                chain.Operands.RemoveAt(chain.Operands.Count - 1);
                chain.Operands.Add(newAnalysis);
                chain.ErroneousOperandIndex = newAnalysis.Index;
                chain.EndLinePosition = _ctx.CurrentLine.LineLength;
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
        _ctx.CurrentLine.SetsFlags = false;
        _ctx.CurrentLine.SetFlagsRange = null;
        _ctx.CurrentLine.CannotSetFlags = false;
        _ctx.CurrentLine.ConditionCode = null;
        _ctx.CurrentLine.ConditionCodeRange = null;
        _ctx.CurrentLine.CannotBeConditional = false;
        _ctx.CurrentLine.HasInvalidConditionCode = false;
        _ctx.CurrentLine.HasUnterminatedConditionCode = false;
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
