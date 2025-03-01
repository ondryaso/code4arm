﻿// VariablePresentationHint.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Serialization;
using Code4Arm.ExecutionCore.Protocol.StringEnum;

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// VariablePresentationHint
/// Optional properties of a variable that can be used to determine how to render the variable in the UI.
/// </summary>
public record VariablePresentationHint
{
    /// <summary>
    /// The kind of variable. Before introducing additional values, try to use the listed values.
    /// Values:
    /// 'property': Indicates that the object is a property.
    /// 'method': Indicates that the object is a method.
    /// 'class': Indicates that the object is a class.
    /// 'data': Indicates that the object is data.
    /// 'event': Indicates that the object is an event.
    /// 'baseClass': Indicates that the object is a base class.
    /// 'innerClass': Indicates that the object is an inner class.
    /// 'interface': Indicates that the object is an interface.
    /// 'mostDerivedClass': Indicates that the object is the most derived class.
    /// 'virtual': Indicates that the object is virtual, that means it is a synthetic object introduced by the adapter for
    /// rendering purposes, e.g. an index range for large arrays.
    /// 'dataBreakpoint': Indicates that a data breakpoint is registered for the object.
    /// etc.
    /// </summary>
    [Optional]
    public VariablePresentationHintKind? Kind { get; init; }

    /// <summary>
    /// Set of attributes represented as an array of strings. Before introducing additional values, try to use the listed
    /// values.
    /// Values:
    /// 'static': Indicates that the object is static.
    /// 'constant': Indicates that the object is a constant.
    /// 'readOnly': Indicates that the object is read only.
    /// 'rawString': Indicates that the object is a raw string.
    /// 'hasObjectId': Indicates that the object can have an Object ID created for it.
    /// 'canHaveObjectId': Indicates that the object has an Object ID associated with it.
    /// 'hasSideEffects': Indicates that the evaluation had side effects.
    /// etc.
    /// </summary>
    [Optional]
    public Container<VariableAttributes>? Attributes { get; init; }

    /// <summary>
    /// Visibility of variable. Before introducing additional values, try to use the listed values.
    /// Values: 'public', 'private', 'protected', 'internal', 'final', etc.
    /// </summary>
    [Optional]
    public VariableVisibility? Visibility { get; init; }

    /// <summary>
    /// If true, clients can present the variable with a UI that supports a
    /// specific gesture to trigger its evaluation.
    /// This mechanism can be used for properties that require executing code when
    /// retrieving their value and where the code execution can be expensive and/or
    /// produce side-effects. A typical example are properties based on a getter
    /// function.
    /// Please note that in addition to the 'lazy' flag, the variable's
    /// 'variablesReference' must refer to a variable that will provide the value
    /// through another 'variable' request.
    /// </summary>
    [Optional]
    public bool Lazy { get; init; }
}

public class VariablePresentationHintKind : StringEnum<VariablePresentationHintKind>
{
    public static readonly VariablePresentationHintKind Property = Create("property");
    public static readonly VariablePresentationHintKind Method = Create("method");
    public static readonly VariablePresentationHintKind Class = Create("class");
    public static readonly VariablePresentationHintKind Data = Create("data");
    public static readonly VariablePresentationHintKind Event = Create("event");
    public static readonly VariablePresentationHintKind BaseClass = Create("baseClass");
    public static readonly VariablePresentationHintKind InnerClass = Create("innerClass");
    public static readonly VariablePresentationHintKind Interface = Create("interface");
    public static readonly VariablePresentationHintKind MostDerivedClass = Create("mostDerivedClass");
    public static readonly VariablePresentationHintKind Virtual = Create("virtual");

    [Obsolete("The 'hasDataBreakpoint' attribute should generally be used instead.")]
    public static readonly VariablePresentationHintKind DataBreakpoint = Create("dataBreakpoint");
}

public class VariableAttributes : StringEnum<VariableAttributes>
{
    public static readonly VariableAttributes Static = Create("static");
    public static readonly VariableAttributes Constant = Create("constant");
    public static readonly VariableAttributes ReadOnly = Create("readOnly");
    public static readonly VariableAttributes RawString = Create("rawString");
    public static readonly VariableAttributes HasObjectId = Create("hasObjectId");
    public static readonly VariableAttributes CanHaveObjectId = Create("canHaveObjectId");
    public static readonly VariableAttributes HasSideEffects = Create("hasSideEffects");
    public static readonly VariableAttributes HasDataBreakpoint = Create("hasDataBreakpoint");
}

public class VariableVisibility : StringEnum<VariableVisibility>
{
    public static readonly VariableVisibility Public = Create("public");
    public static readonly VariableVisibility Private = Create("private");
    public static readonly VariableVisibility Protected = Create("protected");
    public static readonly VariableVisibility Internal = Create("internal");
    public static readonly VariableVisibility Final = Create("final");
}
