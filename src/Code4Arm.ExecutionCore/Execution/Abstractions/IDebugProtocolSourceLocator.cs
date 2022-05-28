// IDebugProtocolSourceLocator.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

/// <summary>
/// Represents a component used to convert between the execution core's internal representation of executable sources
/// and the DAP <see cref="Source"/> models that carry a client-oriented representation of a source file.  
/// </summary>
public interface IDebugProtocolSourceLocator
{
    /// <summary>
    /// Returns an <see cref="IEnumerable{T}"/> of <see cref="Source"/> objects that represent all source files the
    /// current executable has been assembled and linked from.
    /// </summary>
    Task<IEnumerable<Source>> GetSources();

    /// <summary>
    /// Returns the contents of a given source file, identified by a reference assigned to it by this locator.
    /// </summary>
    /// <param name="sourceReference">The source reference number.</param>
    /// <returns>The contents of the source file.</returns>
    /// <exception cref="InvalidSourceException">The provided reference number doesn't correspond to any source.</exception>
    Task<SourceResponse> GetSourceContents(long sourceReference);

    /// <summary>
    /// Returns the contents of a given source file. The target file may be identified either by a reference assigned
    /// to it by this locator, or by it's client path. The identifier is retrieved from a given <see cref="Source"/>
    /// object (the reference number has priority).
    /// </summary>
    /// <param name="source">The <see cref="Source"/> object with <see cref="Source.SourceReference"/> or
    /// <see cref="Source.Path"/> set.</param>
    /// <returns>The contents of the source file.</returns>
    /// <exception cref="InvalidSourceException">The provided <see cref="Source"/> object doesn't carry any valid
    /// identifier of a valid source.</exception>
    Task<SourceResponse> GetSourceContents(Source source);

    /// <summary>
    /// Returns a path of an object file created when assembling a given source file, identified using
    /// a <see cref="Source"/>.
    /// </summary>
    /// <param name="source">The <see cref="Source"/> object with <see cref="Source.SourceReference"/> or
    /// <see cref="Source.Path"/> set.</param>
    /// <returns>The path of the object file corresponding to the source. Null if the provided <see cref="Source"/>
    /// object doesn't carry any valid identifier of a valid source.</returns>
    string? GetCompilationPathForSource(Source source);

    /// <summary>
    /// Returns an <see cref="AssembledObject"/> representation of a object file created when assembling a given source
    /// file.
    /// </summary>
    /// <param name="source">The <see cref="Source"/> object with <see cref="Source.SourceReference"/> or
    /// <see cref="Source.Path"/> set.</param>
    /// <returns>The <see cref="AssembledObject"/>. Null if no such object exists or the provided <see cref="Source"/>
    /// object doesn't carry any valid identifier of a valid source.</returns>
    AssembledObject? GetObjectForSource(Source source);

    /// <summary>
    /// Returns the contents of a given source file.
    /// </summary>
    /// <remarks>
    /// If <see cref="SourceArguments.Source"/> is not null, it is used as the provider of the source identifier
    /// in a call to <see cref="GetSourceContents(Source)"/>. Otherwise, the <see cref="SourceArguments.SourceReference"/>
    /// is used in a call to <see cref="GetSourceContents(long)"/>.
    /// </remarks>
    /// <param name="arguments">A <see cref="SourceArguments"/> container of the source identifier.</param>
    /// <returns>The contents of the source file.</returns>
    Task<SourceResponse> GetSourceContents(SourceArguments arguments)
        => arguments.Source is null
            ? this.GetSourceContents(arguments.SourceReference)
            : this.GetSourceContents(arguments.Source);
}
