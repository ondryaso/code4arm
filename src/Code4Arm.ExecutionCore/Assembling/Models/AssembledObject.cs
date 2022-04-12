// AssembledObject.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Files.Abstractions;
using Microsoft.Extensions.Logging;

namespace Code4Arm.ExecutionCore.Assembling.Models;

public class AssembledObject : IDisposable
{
    private readonly ILogger<AssembledObject> _logger;
    internal string ObjectFilePath { get; }
    internal string AssemblerOutput { get; }
    public string AssemblerErrors { get; }

    public IAsmFile SourceFile { get; }
    public int SourceVersion { get; }
    public bool AssemblySuccessful { get; }

    private bool _fileDeleted;

    internal AssembledObject(IAsmFile sourceFile, int sourceVersion, string objectFilePath, string gasOut,
        string gasErr, bool successful, ILogger<AssembledObject> logger)
    {
        _logger = logger;
        this.AssemblySuccessful = successful;
        this.SourceFile = sourceFile;
        this.SourceVersion = sourceVersion;
        this.ObjectFilePath = objectFilePath;
        this.AssemblerOutput = gasOut;
        this.AssemblerErrors = gasErr;
    }

    internal void DeleteFile()
    {
        if (!_fileDeleted)
        {
            _fileDeleted = true;

            try
            {
                _logger.LogTrace("Deleting temporary object file for {AsmSourceName}.", this.SourceFile.Name);
                File.Delete(this.ObjectFilePath);
            }
            catch (Exception e)
            {
                _logger.LogWarning(e, "Cannot delete temporary object file {ObjectFilePath} for source {AsmSourceName}.",
                    this.ObjectFilePath, this.SourceFile.Name);
            }
        }
    }

    public void Dispose()
    {
        this.DeleteFile();
    }
}
