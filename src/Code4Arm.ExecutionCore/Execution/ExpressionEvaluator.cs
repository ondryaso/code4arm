// ExpressionEvaluator.cs
// Author: Ondřej Ondryáš

using System.Numerics;
using System.Reflection;
using System.Text.RegularExpressions;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.Debugger;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.Unicorn.Constants;
using ELFSharp.ELF.Sections;

namespace Code4Arm.ExecutionCore.Execution;

// Contains the expression evaluating functionality of DebugProvider.
internal partial class DebugProvider
{
    private static readonly Regex TopExpressionRegex = new(
        @"(?:\((?<type>float|single|double|byte|short|hword|int|word|long|dword|sbyte|ushort|uhword|uint|uword|ulong|udword|string)\))?(?<expr>[\w\s\[\],.+\-&]+)(?::(?<format>x|b|d|ieee))?",
        RegexOptions.Compiled);

    private static Regex GetTopExpressionRegex() => TopExpressionRegex;

    private static readonly Regex RegisterRegex = new(
        @"(?:(?<reg>R(?:(?:1[0-5])|[0-9])|PC|LR|SP)|(?:S(?<s_reg>(?:1[0-5])|[0-9]))|(?:D(?<d_reg>31|30|(?:[12][0-9])|[0-9]))|(?:Q(?<q_reg>(?:1[0-5])|[0-9])))(?:\s?\[(?<indexer>[0-9]+)\])?",
        RegexOptions.Compiled);

    private static Regex GetRegisterRegex() => RegisterRegex;

    private static readonly Regex AddressingRegex = new(
        @"\[\s*(?:(?<reg>R(?:(?:1[0-5])|[0-9])|PC|LR|SP)|(?<imm>(?:0x)?[0-9a-fA-F]+)|(?<symbol>[a-zA-Z\._]\w+))\s*(,\s*(?<sign>[+\-])?(?:(?<reg_off>R(?:(?:1[0-5])|[0-9])|PC|LR|SP)|(?<imm_off>(?:0x)?[0-9a-fA-F]+))\s*(,\s*(?<shift>LSL|LSR|ASR|ROR|ROL)\s+(?<imm_shift>(?:0x)?[0-9a-fA-F]+))?)?\s*\]",
        RegexOptions.Compiled);

    private static Regex GetAddressingRegex() => AddressingRegex;

    private int _currentEvaluateId = 0;

    public EvaluateResponse EvaluateExpression(string expression, EvaluateArgumentsContext? context,
        ValueFormat? format)
    {
        // expr!!! variablesReference . childName
        if (expression.StartsWith("!!!") && expression.Length > 3)
            return this.EvaluateDirectVariableExpression(expression, context, format);

        var topLevelMatch = GetTopExpressionRegex().Match(expression);
        var expressionValue = topLevelMatch.Groups["expr"].Value.Trim();

        if (!topLevelMatch.Success || string.IsNullOrEmpty(expressionValue))
            throw new InvalidExpressionException(ExceptionMessages.InvalidExpressionTop);

        // Parse type and format
        var expressionTypeValue = topLevelMatch.Groups["type"].Value;
        var expressionFormatValue = topLevelMatch.Groups["format"].Value;

        var expressionType = string.IsNullOrWhiteSpace(expressionTypeValue)
            ? ExpressionValueType.Default
            : expressionTypeValue switch
            {
                "byte" => ExpressionValueType.ByteU,
                "sbyte" => ExpressionValueType.ByteS,
                "short" or "hword" => ExpressionValueType.ShortS,
                "ushort" or "uhword" => ExpressionValueType.ShortU,
                "int" or "word" => ExpressionValueType.IntS,
                "uint" or "uword" => ExpressionValueType.IntU,
                "long" or "dword" => ExpressionValueType.LongS,
                "ulong" or "udword" => ExpressionValueType.LongU,
                "float" or "single" => ExpressionValueType.Float,
                "double" => ExpressionValueType.Double,
                "string" => ExpressionValueType.String,
                _ => throw new InvalidExpressionException(ExceptionMessages.InvalidExpressionTypeSpecifier)
            };

        var expressionFormat = string.IsNullOrWhiteSpace(expressionFormatValue)
            ? ((format?.Hex ?? false)
                ? ExpressionValueFormat.Hex
                : (ExpressionValueFormat) Options.VariableNumberFormat)
            : expressionFormatValue switch
            {
                "x" => ExpressionValueFormat.Hex,
                "b" => ExpressionValueFormat.Binary,
                "d" => ExpressionValueFormat.Decimal,
                "ieee" => ExpressionValueFormat.Ieee,
                _ => throw new InvalidExpressionException(ExceptionMessages.InvalidExpressionFormatSpecifier)
            };

        // Determine expression type (addressing_expr | register_expr | symbol_addr | variable_path)
        // Use primitive first-character lookup before throwing the regex at the expression
        return expressionValue[0] switch
        {
            '[' => this.EvaluateAddressingExpression(expressionValue, expressionType, expressionFormat),
            'R' or 'S' or 'Q' or 'D' => this.EvaluateRegisterExpression(expressionValue, expressionType,
                expressionFormat),
            '&' => this.EvaluateSymbolAddressExpression(expressionValue, expressionType, expressionFormat),
            _ => this.EvaluateVariablePathExpression(expressionValue, expressionType, expressionFormat, true)!
        };
    }

    private EvaluateResponse EvaluateDirectVariableExpression(string expression, EvaluateArgumentsContext? context,
        ValueFormat? format)
    {
        var divider = expression.IndexOf('!', 3);
        var referenceSpan = expression.AsSpan(3, (divider == -1 ? expression.Length : divider) - 3);

        if (!long.TryParse(referenceSpan, out var reference))
            throw new InvalidExpressionException();

        if (!_variables.TryGetValue(reference, out var toSet))
            throw new InvalidExpressionException();

        if (divider != -1)
        {
            var childName = expression[(divider + 1)..];

            if (!(toSet.Children?.TryGetValue(childName, out toSet) ?? false))
                throw new InvalidExpressionException();
        }

        var ctx = new VariableContext(_engine, _clientCulture!, Options, format);
        var value = toSet.GetEvaluated(ctx);

        return new EvaluateResponse()
        {
            Result = value,
            Type = toSet.Type,
            VariablesReference = toSet.Reference,
            NamedVariables = toSet.Children?.Count ?? 0
        };
    }

    #region Addressing expressions

    private EvaluateResponse EvaluateAddressingExpression(string addressingExpression, ExpressionValueType valueType,
        ExpressionValueFormat format)
    {
        var match = GetAddressingRegex().Match(addressingExpression);

        // If invalid, try to interpret the expression as a variable path; if that fails, throw
        if (!match.Success)
            return this.EvaluateVariablePathExpression(addressingExpression, valueType, format)
                ?? throw new InvalidExpressionException(ExceptionMessages.InvalidExpressionAddressing);

        var address = this.GetAddress(match);

        // No type specified -> assume byte
        if (valueType == ExpressionValueType.Default)
            valueType = ExpressionValueType.ByteU;

        // IEEE format is handled later
        var ctx = new VariableContext(_engine, _clientCulture!, Options,
            format == ExpressionValueFormat.Ieee ? ExpressionValueFormat.Default : format);

        if (valueType == ExpressionValueType.String)
        {
            var variable = new StringVariable($"_expr.{address}", address);

            return variable.GetAsEvaluateResponse(ctx, true);
        }
        else
        {
            var variable = new MemoryVariable($"_expr.{address}", (DebuggerVariableType) valueType,
                address);
            variable.Evaluate(ctx);
            var value = variable.Get(ctx);
            var reference = variable.Reference;

            if (format == ExpressionValueFormat.Ieee && valueType == ExpressionValueType.Float)
            {
                // IEEE format: enclose the memory variable with an EnhancedVariable that adds the IEEE segment
                // subvariables

                reference = ReferenceUtils.MakeReference(ContainerType.ExpressionExtras, address,
                    DebuggerVariableType.Float, _currentEvaluateId++);

                var enhanced = new EnhancedVariable<float, MemoryVariable>(variable, reference,
                    parent => new[]
                    {
                        new SinglePrecisionIeeeSegmentVariable(parent, IeeeSegment.Sign),
                        new SinglePrecisionIeeeSegmentVariable(parent, IeeeSegment.Exponent),
                        new SinglePrecisionIeeeSegmentVariable(parent, IeeeSegment.Mantissa)
                    });

                this.AddOrUpdateVariable(enhanced);
            }

            return new EvaluateResponse()
            {
                Result = value,
                Type = variable.Type,
                MemoryReference = address.ToString(),
                VariablesReference = reference
            };
        }
    }

    private uint GetAddress(Match match)
    {
        uint baseValue;

        if (match.Groups["imm"].Length > 0)
        {
            // Base is a constant
            baseValue = FormattingUtils.ParseNumber32U(match.Groups["imm"].Value, _clientCulture!);
        }
        else if (match.Groups["reg"].Length > 0)
        {
            // Base is a register
            var regId = GetRegisterId(match.Groups["reg"].Value);

            if (regId == -1)
                throw new InvalidExpressionException();

            baseValue = _engine.Engine.RegRead<uint>(regId);
        }
        else
        {
            // Base is a symbol
            var symbolName = match.Groups["symbol"].Value;

            baseValue = this.GetSymbolAddress(symbolName);
        }

        var offset = 0;
        if (match.Groups["imm_off"].Length > 0)
        {
            // A constant offset is used
            offset = unchecked((int) FormattingUtils.ParseNumber32U(match.Groups["imm_off"].Value, _clientCulture!));
        }
        else if (match.Groups["reg_off"].Length > 0)
        {
            // A register value is used as the offset
            var regId = GetRegisterId(match.Groups["reg_off"].Value);

            if (regId == -1)
                throw new InvalidExpressionException();

            offset = _engine.Engine.RegRead<int>(regId);
        }

        // Apply negative sign to the offset if present
        if (match.Groups["sign"].Value == "-")
            offset = -offset;

        if (match.Groups["shift"].Length > 0)
        {
            // Apply shift
            var shiftType = match.Groups["shift"].Value;
            var shiftValue =
                unchecked((int) FormattingUtils.ParseNumber32U(match.Groups["imm_shift"].Value, _clientCulture!));

            offset = shiftType switch
            {
                "LSL" => offset << shiftValue,
                "LSR" => unchecked((int) (((uint) offset) >> shiftValue)),
                "ASR" => offset >> shiftValue,
                "ROR" => unchecked((int) BitOperations.RotateRight((uint) offset, shiftValue)),
                "ROL" => unchecked((int) BitOperations.RotateLeft((uint) offset, shiftValue)),
                _ => throw new InvalidExpressionException()
            };
        }

        return (uint) (baseValue + offset);
    }

    #endregion

    private EvaluateResponse EvaluateRegisterExpression(string registerExpression, ExpressionValueType valueType,
        ExpressionValueFormat format)
    {
        if (valueType == ExpressionValueType.String)
            throw new System.Data.InvalidExpressionException(
                ExceptionMessages.InvalidExpressionTypeSpecifierUnavailable);

        var match = GetRegisterRegex().Match(registerExpression);

        // If invalid, try to interpret the expression as a variable path; if that fails, throw
        if (!match.Success)
            return this.EvaluateVariablePathExpression(registerExpression, valueType, format)
                ?? throw new InvalidExpressionException(ExceptionMessages.InvalidExpressionAddressing);

        var index = match.Groups["indexer"].Length > 0
            ? (int?) int.Parse(match.Groups["indexer"].ValueSpan)
            : null;

        if (match.Groups["reg"].Length > 0)
        {
            // R0–R15
            var valueTypeSize = valueType.GetSize();

            if (valueTypeSize > 4)
                throw new InvalidExpressionException(
                    ExceptionMessages.InvalidExpressionTypeSpecifierUnavailable);

            if (index > ((4 / valueTypeSize) - 1))
                throw new InvalidExpressionException(ExceptionMessages.InvalidExpressionIndexer);

            var debuggerVarType = (valueTypeSize == 4 || valueType == ExpressionValueType.Default)
                ? null
                : (DebuggerVariableType?) valueType;
            var variable = this.GetRegisterVariable(match.Groups["reg"].Value, debuggerVarType, index,
                format == ExpressionValueFormat.Ieee);

            var variableFormat = (VariableNumberFormat) format;

            if (format is ExpressionValueFormat.Default or ExpressionValueFormat.Ieee)
                variableFormat = Options.VariableNumberFormat;
            if (valueType == ExpressionValueType.Float)
                variableFormat = VariableNumberFormat.Float;

            var ctx = new VariableContext(_engine, _clientCulture!, Options, variableFormat);

            return variable.GetAsEvaluateResponse(ctx, true);
        }
        else
        {
            var level = (match.Groups["s_reg"].Length > 0)
                ? 0
                : ((match.Groups["d_reg"].Length > 0) ? 1 : 2);

            var name = level switch
            {
                0 => $"S{match.Groups["s_reg"].Value}",
                1 => $"D{match.Groups["d_reg"].Value}",
                2 => $"Q{match.Groups["q_reg"].Value}"
            };

            var levelSize = (4 << level);
            var valueTypeSize = valueType.GetSize();

            if (valueTypeSize > levelSize)
                throw new InvalidExpressionException(
                    ExceptionMessages.InvalidExpressionTypeSpecifierUnavailable);

            if (index > ((levelSize / valueTypeSize) - 1))
                throw new InvalidExpressionException(ExceptionMessages.InvalidExpressionIndexer);

            var debuggerVarType = (valueTypeSize == levelSize || valueType == ExpressionValueType.Default)
                ? null
                : (DebuggerVariableType?) valueType;

            var variable = this.GetSimdRegisterVariable(name, level, debuggerVarType, index,
                format == ExpressionValueFormat.Ieee);

            var variableFormat = (VariableNumberFormat) format;

            if (format is ExpressionValueFormat.Default or ExpressionValueFormat.Ieee)
                variableFormat = Options.SimdRegistersOptions.PreferFloatRendering
                    ? VariableNumberFormat.Float
                    : Options.VariableNumberFormat;

            if (valueType is ExpressionValueType.Float or ExpressionValueType.Double)
                variableFormat = VariableNumberFormat.Float;

            var ctx = new VariableContext(_engine, _clientCulture!, Options, variableFormat);

            return variable.GetAsEvaluateResponse(ctx, true);
        }

        return new EvaluateResponse();
    }

    private IVariable GetRegisterVariable(string regName, DebuggerVariableType? subtype, int? index, bool ieee)
    {
        var regId = GetRegisterId(regName);
        if (subtype.HasValue || ieee)
        {
            var reference = ReferenceUtils.MakeReference(ContainerType.ExpressionExtras, regId,
                evaluateId: _currentEvaluateId++);
            var rv = new RegisterVariable(reference, regId, regName, subtype ?? DebuggerVariableType.Float,
                ieee || Options.ShowFloatIeeeSubvariables);
            this.AddOrUpdateVariable(rv);

            if (!index.HasValue)
                return rv;

            if (!(rv.Children.FirstOrDefault().Value.Children?.TryGetValue($"[{index}]", out var subVar) ?? false))
                throw new InvalidExpressionException(ExceptionMessages.InvalidExpressionIndexer);

            return subVar;
        }
        else
        {
            if (index is > 0)
                throw new InvalidExpressionException(ExceptionMessages.InvalidExpressionIndexer);

            return new RegisterVariable(0, regId, regName, null, false);
        }
    }

    private IVariable GetSimdRegisterVariable(string regName, int simdLevel, DebuggerVariableType? subtype, int? index,
        bool ieee)
    {
        var regId = GetRegisterId(regName);

        var subtypeArray = subtype.HasValue ? new[] {subtype.Value} : null;
        var simdOptions = new ArmSimdRegisterVariableOptions()
        {
            ShowD = false,
            ShowS = false,
            QSubtypes = simdLevel == 2 ? subtypeArray : null,
            DSubtypes = simdLevel == 1 ? subtypeArray : null,
            SSubtypes = simdLevel == 0 ? subtypeArray : null,
            DIeeeSubvariables = ieee,
            SIeeeSubvariables = ieee,
            PreferFloatRendering = false
        };

        IVariable variable = simdLevel switch
        {
            0 => new ArmSSimdRegisterVariable(Arm.Register.GetSRegisterNumber(regId), simdOptions),
            1 => new ArmDSimdRegisterVariable(Arm.Register.GetDRegisterNumber(regId), simdOptions),
            2 => new ArmQSimdRegisterVariable(Arm.Register.GetQRegisterNumber(regId), simdOptions),
            _ => throw new ArgumentException("Invalid SIMD level.", nameof(simdLevel))
        };

        if (subtype.HasValue || ieee)
        {
            var reference = ReferenceUtils.MakeReference(ContainerType.ExpressionExtras, regId, simdLevel: simdLevel,
                evaluateId: _currentEvaluateId++);

            // Encapsulate the SIMD variable to provide a custom reference
            var enhanced = new EnhancedVariable<IVariable>(variable, reference);
            this.AddOrUpdateVariable(enhanced);

            if (!index.HasValue)
                return enhanced;

            if (!(enhanced.Children?.FirstOrDefault().Value.Children?.TryGetValue($"[{index}]", out var subVar)
                    ?? false))
                throw new InvalidExpressionException(ExceptionMessages.InvalidExpressionIndexer);

            return subVar;
        }
        else
        {
            if (index is > 0)
                throw new InvalidExpressionException(ExceptionMessages.InvalidExpressionIndexer);

            if (variable.Reference != 0)
                throw new Exception("Invalid variable state.");

            return variable;
        }
    }

    private EvaluateResponse EvaluateSymbolAddressExpression(string symbolAddressExpression,
        ExpressionValueType valueType, ExpressionValueFormat format)
    {
        var symbolName = symbolAddressExpression[1..];
        var address = this.GetSymbolAddress(symbolName);

        format = format switch
        {
            ExpressionValueFormat.Default => ExpressionValueFormat.Hex,
            ExpressionValueFormat.Ieee => ExpressionValueFormat.Hex,
            _ => format
        };

        // TODO: Create dummy container variable to store the corresponding data symbol variable if it exists

        return new EvaluateResponse()
        {
            Result = FormattingUtils.FormatVariable(address,
                new VariableContext(null!, _clientCulture!, Options, format)),
            Type = "address",
            MemoryReference = address.ToString()
        };
    }

    private EvaluateResponse? EvaluateVariablePathExpression(string variablePathExpression,
        ExpressionValueType valueType, ExpressionValueFormat format, bool throwOnFailure = false)
    {
        if (valueType == ExpressionValueType.String)
            throw new InvalidExpressionException(ExceptionMessages.InvalidExpressionTypeSpecifier);

        if (format == ExpressionValueFormat.Ieee)
            format = ExpressionValueFormat.Default;

        var parts = variablePathExpression.Split('.');

        if (!_topLevel.TryGetValue(parts[0], out var topVariable))
            if (throwOnFailure)
                throw new InvalidExpressionException(ExceptionMessages.InvalidVariable);
            else
                return null;

        var targetVariable = topVariable;

        for (var i = 1; i < parts.Length; i++)
        {
            var varName = parts[i];

            if (targetVariable.Children == null || !targetVariable.Children.TryGetValue(varName, out targetVariable))
                if (throwOnFailure)
                    throw new InvalidExpressionException($"Invalid variable in path: {varName}");
                else
                    return null;
        }

        if (valueType != ExpressionValueType.Default)
        {
            var varType = (DebuggerVariableType) valueType;
            // TODO: try to get matching subvalue child?
        }

        var ctx = new VariableContext(_engine, _clientCulture!, Options, (VariableNumberFormat) format);
        targetVariable.Evaluate(ctx);
        var val = targetVariable.Get(ctx);

        return new EvaluateResponse()
        {
            Result = val,
            Type = targetVariable.Type,
            VariablesReference = targetVariable.Reference,
            NamedVariables = targetVariable.Children?.Count ?? 0
        };
    }

    public SetExpressionResponse SetExpression(string expression, string value, ValueFormat? format)
    {
        this.CheckInitialized();

        if (expression.StartsWith("!!!") && expression.Length > 3)
        {
            var divider = expression.IndexOf('!', 3);
            var referenceSpan = expression.AsSpan(3, (divider == -1 ? expression.Length : divider) - 3);

            if (!long.TryParse(referenceSpan, out var reference))
                throw new InvalidExpressionException();

            if (!_variables.TryGetValue(reference, out var toSet))
                throw new InvalidExpressionException();

            if (divider != -1)
            {
                var childName = expression[(divider + 1)..];

                if (!(toSet.Children?.TryGetValue(childName, out toSet) ?? false))
                    throw new InvalidExpressionException();
            }

            var ctx = new VariableContext(_engine, _clientCulture!, Options, format);
            toSet.Set(value, ctx);

            while (toSet.IsViewOfParent)
            {
                if (toSet.Parent == null)
                    break;

                toSet = toSet.Parent;
            }

            toSet.Evaluate(ctx);
            var val = toSet.Get(ctx);
            ;

            return new SetExpressionResponse()
            {
                Type = toSet.Type,
                Value = val,
                VariablesReference = toSet.Reference
            };
        }

        throw new InvalidExpressionException();
    }

    private static int GetRegisterId(string name)
    {
        var constsType = typeof(Arm.Register);
        var field = constsType.GetField(name.ToUpperInvariant(), BindingFlags.Public | BindingFlags.Static);
        var fieldVal = field?.GetRawConstantValue();

        if (fieldVal == null)
            return -1;

        return (int) fieldVal;
    }

    private uint GetSymbolAddress(string symbolName)
    {
        if ((_engine.ExecutableInfo as Executable)?.Elf.Sections.FirstOrDefault(s =>
                s.Type == SectionType.SymbolTable) is not SymbolTable<uint> symTab)
            throw new InvalidExpressionException();

        var symbol =
            symTab.Entries.FirstOrDefault(s => s.Name.Equals(symbolName, StringComparison.InvariantCulture));

        if (symbol is null)
            throw new InvalidExpressionException();

        return symbol.Value;
    }
}

/*
 Expression EBNF:
 
    in_expr     = [ type ], expr, [ format ] | direct_reference_expr;
    type        = "(", type_name, ")" ;
    type_name   = "float" | "single" | "double" | "byte"   | "short" | "hword" | "int"   | "word"   | "long" 
                | "dword" | "sbyte"  | "ushort" | "uhword" | "uint"  | "uword" | "ulong" | "udword" | "string" ;
                  
    format      = ":", format_type ;
    format_type = "x" | "b" | "ieee" | "d" ;

    direct_reference_expr = "!!!", { digit }+, ".", string ;
    expr = addressing_expr | register_expr | variable_path | symbol_addr ;
    
    addressing_expr = "[", address_expr, [ ",", expr_offset ], "]" ;
    address_expr    = reg_name | imm | symbol ;
    expr_offset     = sign, offset_expr, [ "," shift " " imm ] ;
    offset_expr     = reg_name | imm ;
    sign            = "+" | "-" | "" ;
    reg_name        = "R0" | "R1" | ... | "R15" | "PC" | "LR" | "SP" ;
    shift           = "LSL" | "LSR" | "ASR" | "ROR" | "ROL" ;
    imm             = [ "0x" ], { digit }+ ; 
    symbol          = string ;
    
    variable_path = string, { ".", string }, [ "." ] ;
    
    symbol_addr   = "&", string ;
     
    register_expr = reg_name, [ indexer ] | s_reg_name, [ indexer ] | d_reg_name, [ indexer ] | q_reg_name, [ indexer ] ;
    
    s_reg_name    = "S0" | "S1" | ... | "S15" ;
    d_reg_name    = "D0" | "D1" | ... | "D31" ;
    q_reg_name    = "Q0" | "Q1" | ... | "Q15" ;
    
    indexer    = "[", { digit }+, "]" ;
*/
