// OptionalAttribute.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

namespace Code4Arm.ExecutionCore.Protocol.Serialization;

[AttributeUsage(AttributeTargets.Property)]
public class OptionalAttribute : Attribute
{
}
