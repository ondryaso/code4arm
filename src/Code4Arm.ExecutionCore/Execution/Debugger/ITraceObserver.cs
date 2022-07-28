// ITraceObserver.cs
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

namespace Code4Arm.ExecutionCore.Execution.Debugger;

/// <summary>
/// An observer for traceable changes.
/// </summary>
public interface ITraceObserver
{
    /// <summary>
    /// Creates a <see cref="VariableContext"/> used by the traceables to format the values.
    /// </summary>
    VariableContext GetTraceTriggerContext();
    
    /// <summary>
    /// Called by the traceables to notify that their values have changed.
    /// </summary>
    /// <param name="traceId">The observer-specific identifier the observer has registered itself with.</param>
    void TraceTriggered(long traceId);
}

/// <summary>
/// A typed observer for typed traceable changes.
/// </summary>
/// <typeparam name="TTracedValue">The value of the traced field.</typeparam>
public interface ITraceObserver<in TTracedValue> : ITraceObserver
{
    /// <summary>
    /// Called by the traceables to notify that their values have changed.
    /// </summary>
    /// <remarks>
    /// It is expected that typed observers are only notified once and using the typed value, even if they register using
    /// the untyped equivalent of this method. However, if the observer is also a <see cref="IFormattedTraceObserver"/>,
    /// only its <see cref="TraceTriggered"/> method will be called.
    /// </remarks>
    /// <param name="traceId">The observer-specific identifier the observer has registered itself with.</param>
    /// <param name="oldValue">The previous value of the traced field.</param>
    /// <param name="newValue">The new value of the traced field.</param>
    void TraceTriggered(long traceId, TTracedValue oldValue, TTracedValue newValue);
}

/// <summary>
/// An observer typed with <see cref="string"/> that receives trace triggered events with formatted values of the
/// traced field.
/// </summary>
public interface IFormattedTraceObserver : ITraceObserver<string?>
{
}
