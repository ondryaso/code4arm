// IAssembler.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Files.Abstractions;

namespace Code4Arm.ExecutionCore.Assembling.Abstractions;

public interface IAssembler : IDisposable
{
    /// <summary>
    /// Assembles a given file using GAS and returns a descriptor object wrapping the resulting object file and the
    /// assembly listing.
    /// </summary>
    /// <remarks>
    /// The output object file is saved to a temporary location. The returned <see cref="AssembledObject"/> deletes
    /// the file when disposed.<br/>
    /// The execution time of GAS is limited by the configured <see cref="AssemblerOptions.TimeoutMs"/>.
    /// </remarks>
    /// <param name="file">The assembly source file.</param>
    /// <returns>An <see cref="AssembledObject"/> descriptor object of the assembled object file.</returns>
    /// <exception cref="Exception">GAS process couldn't be started or its execution timed out.</exception>
    Task<AssembledObject> AssembleFile(IAsmFile file);

    /// <summary>
    /// Assembles all files in a given <see cref="IAsmMakeTarget"/> and links them, resulting in an ELF executable binary.
    /// When successful, reads the binary and creates an <see cref="Executable"/>.
    /// </summary>
    /// <remarks>
    /// The output object file is saved to a temporary location. The returned <see cref="Executable"/> deletes
    /// the file when disposed.<br/>
    /// The execution time of LD is limited by the configured <see cref="LinkerOptions.TimeoutMs"/>.
    /// </remarks>
    /// <param name="asmMakeTarget">The <see cref="IAsmMakeTarget"/> to get source files from.</param>
    /// <returns>
    /// A structure describing the process result.
    /// When some of the files fail to assemble, <see cref="MakeResult.State"/> is set to
    /// <see cref="MakeResultState.InvalidObjects"/> and <see cref="MakeResult.InvalidObjects"/> is populated.
    /// When the files cannot be linked together, <see cref="MakeResult.State"/> is set to
    /// <see cref="MakeResultState.LinkingError"/> and <see cref="MakeResult.LinkerError"/> is populated.
    /// <see cref="MakeResult.Executable"/> is only populated when the process succeeds and
    /// <see cref="MakeResult.State"/> is <see cref="MakeResultState.Successful"/>.
    /// </returns>
    /// <exception cref="Exception">LD process couldn't be started or its execution timed out.</exception>
    Task<MakeResult> MakeProject(IAsmMakeTarget asmMakeTarget);

    void UseFunctionSimulators(IEnumerable<IFunctionSimulator> simulators);
}
