// Assembler.cs
// Author: Ondřej Ondryáš

using System.Diagnostics;
using System.Text.RegularExpressions;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Files.Abstractions;
using ELFSharp.ELF;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Code4Arm.ExecutionCore.Assembling;

public class Assembler : IDisposable
{
    private readonly IOptionsSnapshot<AssemblerOptions> _assemblerOptions;
    private readonly IOptionsSnapshot<LinkerOptions> _linkerOptions;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<Assembler> _logger;

    private string? _linkerScriptPath = null;
    private List<BoundFunctionSimulator>? _functionSimulators = null;

    public Assembler(IOptionsSnapshot<AssemblerOptions> assemblerOptions, IOptionsSnapshot<LinkerOptions> linkerOptions,
        ILoggerFactory loggerFactory)
    {
        _assemblerOptions = assemblerOptions;
        _linkerOptions = linkerOptions;
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<Assembler>();
    }

    private static readonly Regex FileNameRegex = new(@"^(?:.*?):\s*", RegexOptions.Multiline | RegexOptions.Compiled);

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
    public async Task<AssembledObject> AssembleFile(IAsmFile file)
    {
        _logger.LogDebug("Assembling file {Name} [{Version}].", file.Name, file.Version);
        using var location = await file.LocateAsync();
        _logger.LogTrace("Path: {Location}.", location.FileSystemPath);

        var gasStartInfo = new ProcessStartInfo(_assemblerOptions.Value.GasPath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        var outputFile = Path.GetTempFileName();
        if (_assemblerOptions.Value.GasOptions != null)
        {
            foreach (var gasOption in _assemblerOptions.Value.GasOptions)
            {
                gasStartInfo.ArgumentList.Add(gasOption);
            }
        }

        gasStartInfo.ArgumentList.Add("-alscn");
        gasStartInfo.ArgumentList.Add("-o");
        gasStartInfo.ArgumentList.Add(outputFile);
        gasStartInfo.ArgumentList.Add(location.FileSystemPath);

        using var gasProcess = Process.Start(gasStartInfo);
        if (gasProcess == null)
        {
            _logger.LogError("Error starting GAS process.");
            throw new Exception("Error starting GAS process.");
        }

        var cts = new CancellationTokenSource(_assemblerOptions.Value.TimeoutMs);

        try
        {
            await gasProcess.WaitForExitAsync(cts.Token);
        }
        catch (TaskCanceledException e)
        {
            _logger.LogWarning("GAS process timed out for file {Name}.", file.Name);
            throw new Exception("GAS process timed out.", e);
        }

        var stdout = await gasProcess.StandardOutput.ReadToEndAsync();
        var stderr = await gasProcess.StandardError.ReadToEndAsync();

        if (!string.IsNullOrWhiteSpace(stderr))
        {
            stderr = FileNameRegex.Replace(stderr, string.Empty);
            _logger.LogDebug("Assembling error for file {Name}.", file.Name);
            _logger.LogTrace("stderr output: {Error}", stderr);
        }

        _logger.LogTrace("File {Name} [{Version}] assembly ended with code {Code}.", file.Name, file.Version,
            gasProcess.ExitCode);

        return new AssembledObject(file, location.Version, outputFile, stdout, stderr, gasProcess.ExitCode == 0,
            _loggerFactory.CreateLogger<AssembledObject>());
    }

    /// <summary>
    /// Assembles all files in a given <see cref="IAsmProject"/> and links them, resulting in an ELF executable binary.
    /// When successful, reads the binary and creates an <see cref="Executable"/>. 
    /// </summary>
    /// <remarks>
    /// The output object file is saved to a temporary location. The returned <see cref="Executable"/> deletes
    /// the file when disposed.<br/>
    /// The execution time of LD is limited by the configured <see cref="LinkerOptions.TimeoutMs"/>. 
    /// </remarks>
    /// <param name="asmProject">The <see cref="IAsmProject"/> to get source files from.</param>
    /// <returns>A structure describing the process result.
    /// When some of the files fail to assemble, <see cref="MakeResult.State"/> is set to
    /// <see cref="MakeResultState.InvalidObjects"/> and <see cref="MakeResult.InvalidObjects"/> is populated.
    /// When the files cannot be linked together, <see cref="MakeResult.State"/> is set to
    /// <see cref="MakeResultState.LinkingError"/> and <see cref="MakeResult.LinkerError"/> is populated.
    /// <see cref="MakeResult.Executable"/> is only populated when the process succeeds and
    /// <see cref="MakeResult.State"/> is <see cref="MakeResultState.Successful"/>.</returns>
    /// <exception cref="Exception">LD process couldn't be started or its execution timed out.</exception>
    public async Task<MakeResult> MakeProject(IAsmProject asmProject)
    {
        _logger.LogDebug("Making project {Name}.", asmProject.Name);
        var validObjects = new List<AssembledObject>();
        List<AssembledObject>? invalidObjects = null;

        // Assemble all
        foreach (var asmFile in asmProject.GetFiles())
        {
            var assembled = await this.AssembleFile(asmFile);
            if (assembled.AssemblySuccessful)
            {
                validObjects.Add(assembled);
            }
            else
            {
                invalidObjects ??= new List<AssembledObject>();
                invalidObjects.Add(assembled);
            }
        }

        // Any unsuccessful files => failure
        if (invalidObjects != null)
        {
            CleanObjects(validObjects);

            _logger.LogTrace("Not linking – invalid object file(s).");
            return new MakeResult(asmProject, MakeResultState.InvalidObjects, null, validObjects, invalidObjects, null);
        }

        // Link
        var ldStartInfo = new ProcessStartInfo(_linkerOptions.Value.LdPath)
        {
            // RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        var outputFile = Path.GetTempFileName();

        if (_linkerOptions.Value.LdOptions != null) // Options to place BEFORE object files
        {
            foreach (var ldOption in _linkerOptions.Value.LdOptions)
            {
                ldStartInfo.ArgumentList.Add(ldOption);
            }
        }

        ldStartInfo.ArgumentList.Add("-o"); // Output file
        ldStartInfo.ArgumentList.Add(outputFile);
        ldStartInfo.ArgumentList.Add("-z"); // Page size
        ldStartInfo.ArgumentList.Add("common-page-size=4096");

        if (_linkerScriptPath != null) // Linker script (if we have one)
        {
            ldStartInfo.ArgumentList.Add(_linkerScriptPath);
        }

        foreach (var assembledObject in validObjects) // Object files
        {
            ldStartInfo.ArgumentList.Add(assembledObject.ObjectFilePath);
        }

        if (_linkerOptions.Value.LdTrailOptions != null) // Options to place AFTER object files
        {
            foreach (var ldOption in _linkerOptions.Value.LdTrailOptions)
            {
                ldStartInfo.ArgumentList.Add(ldOption);
            }
        }

        _logger.LogTrace("Starting the linker.");
        using var ldProcess = Process.Start(ldStartInfo);
        if (ldProcess == null)
        {
            CleanObjects(validObjects);
            _logger.LogError("Error starting LD process.");
            throw new Exception("Error starting LD process.");
        }

        var cts = new CancellationTokenSource(_linkerOptions.Value.TimeoutMs);

        try
        {
            await ldProcess.WaitForExitAsync(cts.Token);
        }
        catch (TaskCanceledException e)
        {
            CleanObjects(validObjects);
            _logger.LogWarning("LD process timed out for project {Name}.", asmProject.Name);
            throw new Exception("LD process timed out.", e);
        }

        var stderr = await ldProcess.StandardError.ReadToEndAsync();

        if (!string.IsNullOrWhiteSpace(stderr))
        {
            stderr = stderr.Replace(_linkerOptions.Value.LdPath + ":", string.Empty);
            _logger.LogDebug("Linking error for project {Name}.", asmProject.Name);
            _logger.LogTrace("stderr output: {Error}", stderr);
        }

        _logger.LogTrace("Project {Name} linking ended with code {Code}.", asmProject.Name, ldProcess.ExitCode);

        var success = ldProcess.ExitCode == 0;

        Executable? retExe = null;
        if (success)
        {
            retExe = this.MakeExecutable(asmProject, validObjects, outputFile);
            foreach (var assembledObject in validObjects)
            {
                assembledObject.DeleteFile();
            }
        }
        else
        {
            CleanObjects(validObjects);
        }

        return new MakeResult(asmProject, success ? MakeResultState.Successful : MakeResultState.LinkingError, retExe,
            validObjects, null, stderr);
    }

    private Executable MakeExecutable(IAsmProject project, List<AssembledObject> assembledObjects, string elfPath)
    {
        if (!ELFReader.TryLoad(elfPath, out ELF<uint> elf))
        {
            throw new Exception("Cannot load linked ELF file.");
        }

        var exe = new Executable(project, elfPath, elf, assembledObjects, _functionSimulators,
            _loggerFactory.CreateLogger<Executable>());

        return exe;
    }

    private static void CleanObjects(List<AssembledObject> assembledObjects) =>
        assembledObjects.ForEach(a => a.Dispose());

    public void UseFunctionSimulators(IEnumerable<IFunctionSimulator> simulators)
    {
        _functionSimulators = new List<BoundFunctionSimulator>();
        var address = _linkerOptions.Value.TrampolineStartAddress;
        foreach (var functionSimulator in simulators)
        {
            _logger.LogTrace("Using function simulator {Name} at address {Address:x8}.", functionSimulator.Name,
                address);

            _functionSimulators.Add(new BoundFunctionSimulator(functionSimulator, address));
            address += 4;
        }

        this.MakeLinkerScript();
    }

    private void MakeLinkerScript()
    {
        if (_linkerScriptPath != null)
        {
            try
            {
                File.Delete(_linkerScriptPath);
            }
            catch (Exception e)
            {
                _logger.LogWarning(e,
                    "Cannot delete temporary linker script file {FilePath}.",
                    _linkerScriptPath);
            }
        }

        if (_functionSimulators is null or { Count: 0 })
        {
            _linkerScriptPath = null;
            return;
        }

        _linkerScriptPath = Path.GetTempFileName();
        using var sw = new StreamWriter(_linkerScriptPath);
        foreach (var (functionSimulator, address) in _functionSimulators)
        {
            sw.Write($"PROVIDE_HIDDEN({functionSimulator.Name} = 0x{address:x8});");
        }
    }

    public void Dispose()
    {
        if (_linkerScriptPath != null)
        {
            try
            {
                File.Delete(_linkerScriptPath);
            }
            catch (Exception e)
            {
                _logger.LogWarning(e,
                    "Cannot delete temporary linker script file {FilePath}.",
                    _linkerScriptPath);
            }

            _linkerScriptPath = null;
        }
    }
}
