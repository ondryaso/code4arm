// AssembledObject.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Files.Abstractions;
using Microsoft.Extensions.Logging;

namespace Code4Arm.ExecutionCore.Assembling.Models;

public class AssembledObject : IDisposable
{
    private readonly ILogger<AssembledObject> _logger;
    private bool _fileDeleted;

    internal string ObjectFilePath { get; }
    internal string AssemblerOutput { get; }
    public string AssemblerErrors { get; }

    public IAsmFile SourceFile { get; }
    public int SourceVersion { get; }
    public bool AssemblySuccessful { get; }

    internal AssembledObject(IAsmFile sourceFile, int sourceVersion, string objectFilePath, string gasOut,
        string gasErr, bool successful, ILogger<AssembledObject> logger)
    {
        _logger = logger;
        AssemblySuccessful = successful;
        SourceFile = sourceFile;
        SourceVersion = sourceVersion;
        ObjectFilePath = objectFilePath;
        AssemblerOutput = gasOut;
        AssemblerErrors = gasErr;
    }

    internal void DeleteFile()
    {
        if (!_fileDeleted)
        {
            _fileDeleted = true;

            try
            {
                _logger.LogTrace("Deleting temporary object file for {AsmSourceName}.", SourceFile.Name);
                File.Delete(ObjectFilePath);
            }
            catch (Exception e)
            {
                _logger.LogWarning(e,
                    "Cannot delete temporary object file {ObjectFilePath} for source {AsmSourceName}.",
                    ObjectFilePath, SourceFile.Name);
            }
        }
    }

    public void Dispose()
    {
        this.DeleteFile();
    }
}
