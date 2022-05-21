// ExpressionEvaluator.cs
// Author: Ondřej Ondryáš

using System.Numerics;
using System.Reflection;
using System.Text.RegularExpressions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.Debugger;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution;

internal partial class DebugProvider
{
    private static readonly Regex TopExpressionRegex = new(
        @"(?:\((?<type>float|single|double|byte|short|hword|int|word|long|dword|sbyte|ushort|uhword|uint|uword|ulong|udword|string)\))?(?<expr>[\w\s\[\],.+\-]+)(?::(?<format>x|b|ieee))?",
        RegexOptions.Compiled);

    private static Regex GetTopExpressionRegex() => TopExpressionRegex;

    private static readonly Regex RegisterRegex = new(
        @"(?:(?<reg>R(?:(?:1[0-5])|[0-9])|PC|LR|SP)(?:\.(?<divider>bytes|shorts|hwords)(?:\[(?<indexer>[0-9]+)\])?)?)|(?:(?:S(?<s_reg>(?:1[0-5])|[0-9]))(?:\.(?<divider>bytes|shorts|hwords)(?:\[(?<indexer>[0-9]+)\])?)?)|(?:(?:D(?<s_reg>31|30|(?:[12][0-9])|[0-9]))(?:\.(?<divider>bytes|shorts|hwords|ints|words)(?:\[(?<indexer>[0-9]+)\])?)?)|(?:(?:Q(?<s_reg>(?:1[0-5])|[0-9])(?:\.(?<divider>bytes|shorts|hwords|ints|words|longs|dwords)(?:\[(?<indexer>[0-9]+)\])?)?))",
        RegexOptions.Compiled);

    private static Regex GetRegisterRegex() => RegisterRegex;

    private static readonly Regex AddressingRegex = new(
        @"\[(?:(?<reg>R(?:(?:1[0-5])|[0-9])|PC|LR|SP)|(?<imm>(?:0x)?[0-9a-fA-F]+)|(?<symbol>[a-zA-Z\._]\w+))(,(?<sign>[+\-])?(?:(?<reg_off>R(?:(?:1[0-5])|[0-9])|PC|LR|SP)|(?<imm_off>(?:0x)?[0-9a-fA-F]+))(,(?<shift>LSL|LSR|ASR|ROR|ROL)\s+(?<imm_shift>(?:0x)?[0-9a-fA-F]+))?)?\]",
        RegexOptions.Compiled);

    private static Regex GetAddressingRegex() => AddressingRegex;

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
            ? ((format?.Hex ?? false) ? ExpressionValueFormat.Hex : (ExpressionValueFormat)Options.VariableNumberFormat)
            : expressionFormatValue switch
            {
                "x" => ExpressionValueFormat.Hex,
                "b" => ExpressionValueFormat.Binary,
                "ieee" => ExpressionValueFormat.Ieee,
                _ => throw new InvalidExpressionException(ExceptionMessages.InvalidExpressionFormatSpecifier)
            };

        // Determine expression type (addressing_expr | register_expr | symbol_addr | variable_path)
        // Use primitive first-character lookup before throwing the regex at the expression
        switch (expressionValue[0])
        {
            case '[':
                return this.EvaluateAddressingExpression(expressionValue, expressionType, expressionFormat);
            case 'R' or 'S' or 'Q' or 'D':
                return this.EvaluateRegisterExpression(expressionValue, expressionType, expressionFormat);
            case '&':
                return this.EvaluateSymbolAddressExpression(expressionValue, expressionType, expressionFormat);
            default:
                return this.EvaluateVariablePathExpression(expressionValue, expressionType, expressionFormat, true)!;
        }
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
        if (valueType == ExpressionValueType.Default)
            valueType = ExpressionValueType.ByteU;

        if (valueType is ExpressionValueType.Float or ExpressionValueType.Double &&
            format == ExpressionValueFormat.Ieee)
        {
            // TODO: IEEE subvariables
        }

        var varFormat = format switch
        {
            ExpressionValueFormat.Binary => VariableNumberFormat.Binary,
            ExpressionValueFormat.Hex => VariableNumberFormat.Hex,
            ExpressionValueFormat.Default => VariableNumberFormat.Decimal,
            ExpressionValueFormat.Ieee => VariableNumberFormat.Decimal, // TODO
            _ => VariableNumberFormat.Decimal
        };

        var ctx = new VariableContext(_engine, _clientCulture!, Options, varFormat);
        if (valueType == ExpressionValueType.String)
        {
            // TODO
            return new EvaluateResponse()
            {
                Result = "TODO",
                Type = "Null-terminated string"
            };
        }
        else
        {
            var variable = new MemoryVariable($"_expr.{address}", (DebuggerVariableType)(uint)valueType,
                address);
            variable.Evaluate(ctx);
            var value = variable.Get(ctx);

            return new EvaluateResponse()
            {
                Result = value,
                Type = ((DebuggerVariableType)(uint)valueType).GetName(),
                VariablesReference = 0 // TODO
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
        else
        {
            // Base is a register
            var regId = GetRegisterId(match.Groups["reg"].Value);

            if (regId == -1)
                throw new InvalidExpressionException();

            baseValue = _engine.Engine.RegRead<uint>(regId);
        }

        var offset = 0;
        if (match.Groups["imm_off"].Length > 0)
        {
            // A constant offset is used
            offset = unchecked((int)FormattingUtils.ParseNumber32U(match.Groups["imm_off"].Value, _clientCulture!));
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
                unchecked((int)FormattingUtils.ParseNumber32U(match.Groups["imm_shift"].Value, _clientCulture!));

            offset = shiftType switch
            {
                "LSL" => offset << shiftValue,
                "LSR" => unchecked((int)(((uint)offset) >> shiftValue)),
                "ASR" => offset >> shiftValue,
                "ROR" => unchecked((int)BitOperations.RotateRight((uint)offset, shiftValue)),
                "ROL" => unchecked((int)BitOperations.RotateLeft((uint)offset, shiftValue)),
                _ => throw new InvalidExpressionException()
            };
        }

        return (uint)(baseValue + offset);
    }

    #endregion

    private EvaluateResponse EvaluateRegisterExpression(string registerExpression, ExpressionValueType valueType,
        ExpressionValueFormat format)
    {
        throw new NotImplementedException();
    }

    private EvaluateResponse EvaluateSymbolAddressExpression(string symbolAddressExpression,
        ExpressionValueType valueType, ExpressionValueFormat format)
    {
        throw new NotImplementedException();
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
            var varType = (DebuggerVariableType)valueType;
            // TODO: try to get matching subvalue child?
        }

        var ctx = new VariableContext(_engine, _clientCulture!, Options, (VariableNumberFormat)format);
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

        return (int)fieldVal;
    }
}

/*
 Expression EBNF:
 
    in_expr     ::= [ type ] expr [ format ] | direct_reference_expr;
    type        ::= "(" type_name ")" ;
    type_name   ::= "float" | "single" | "double" | "byte"   | "short" | "hword" | "int"   | "word"   | "long" 
                  | "dword" | "sbyte"  | "ushort" | "uhword" | "uint"  | "uword" | "ulong" | "udword" | "string" ;
                  
    format      ::= ":" format_type ;
    format_type ::= "x" | "b" | "ieee" ;

    direct_reference_expr ::= "!!!" { digit } "." string ;
    expr ::= addressing_expr | register_expr | symbol_addr | variable_path ;
    
    addressing_expr ::= "[" address_expr [ "," expr_offset ] "]" ;
    address_expr    ::= reg_name | imm | symbol ;
    expr_offset     ::= sign offset_expr [ "," shift " " imm ] ;
    offset_expr     ::= reg_name | imm ;
    sign            ::= "+" | "-" | "" ;
    reg_name        ::= "R0" | "R1" | ... | "R15" | "PC" | "LR" | "SP" ;
    shift           ::= "LSL" | "LSR" | "ASR" | "ROR" | "ROL" ;
    imm             ::= [ "0x" ] { digit } ; 
    symbol          ::= string ;
    
    variable_path ::= string { "." string } [ "." ] ;
    
    symbol_addr   ::= "&" string ;
     
    register_expr ::= reg_name [ "." divider32 [ indexer ] ] | s_reg_name [ "." divider32 [ indexer ] ] 
                    | d_reg_name [ "." divider64 [ indexer ] ] | q_reg_name [ "." divider128 [ indexer ] ] ;
    
    s_reg_name    ::= "S0" | "S1" | ... | "S15" ;
    d_reg_name    ::= "D0" | "D1" | ... | "D31" ;
    q_reg_name    ::= "Q0" | "Q1" | ... | "Q15" ;

    divider32  ::= "bytes" | "shorts" | "hwords"  ;
    divider64  ::= "ints"  | "words"  | divider32 ;
    divider128 ::= "longs" | "dwords" | divider64 ;
    
    indexer    ::= "[" { digit } "]" ;
*/
