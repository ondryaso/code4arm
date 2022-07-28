// IVariable.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

using Code4Arm.ExecutionCore.Execution.Exceptions;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

/// <summary>
/// Represents a Variable that can retrieve its value from the emulated program, return it as a formatted string
/// and optionally set it from a properly formatted string. 
/// </summary>
public interface IVariable
{
    /// <summary>
    /// The variable's name.
    /// </summary>
    string Name { get; }
    
    /// <summary>
    /// A human-readable type hint to show for this variable.
    /// </summary>
    string? Type { get; }
    
    /// <summary>
    /// The variable's reference number.
    /// </summary>
    long Reference { get; }
    
    /// <summary>
    /// The variable can be set.
    /// </summary>
    bool CanSet { get; }

    /// <summary>
    /// If true, this child variable is a view over its parent's data.
    /// The Evaluate() method of a parent variable will be called to make this variable's value.
    /// When setting the variable, the whole parent tree should be updated (the protocol doesn't support this though).
    /// </summary>
    bool IsViewOfParent { get; }

    IReadOnlyDictionary<string, IVariable>? Children { get; }
    IVariable? Parent { get; }

    /// <summary>
    /// Retrieves the current value of the variable.
    /// </summary>
    void Evaluate(VariableContext context);
    
    /// <summary>
    /// Returns the last retrieved value of the variable, formatted according to the configuration
    /// in a given <see cref="VariableContext"/>.
    /// </summary>
    /// <seealso cref="Evaluate"/>
    string Get(VariableContext context);
    
    /// <summary>
    /// Attempts to set the variable's value.
    /// </summary>
    /// <exception cref="InvalidVariableFormatException">The provided value cannot be used for this variable.</exception>
    void Set(string value, VariableContext context);
}

/// <summary>
/// Represents a Variable backed with a value of a certain type.
/// </summary>
/// <typeparam name="TBackingValue">The type backing this variable.</typeparam>
public interface IBackedVariable<out TBackingValue> : IVariable
{
    TBackingValue GetBackingValue(VariableContext context);
}

/// <summary>
/// Represents a Variable backed with a value of a certain type that can also be assigned a value of this type. 
/// </summary>
/// <typeparam name="TBackingValue">The type backing this variable.</typeparam>
public interface ISettableBackedVariable<TBackingValue> : IBackedVariable<TBackingValue>
{
    void Set(TBackingValue value, VariableContext context);
}

/// <summary>
/// Represents a Variable backed with a memory field with a specific address.
/// </summary>
public interface IAddressBackedVariable : IVariable
{
    uint GetAddress();
}
