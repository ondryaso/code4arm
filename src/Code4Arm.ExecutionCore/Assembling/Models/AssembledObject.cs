// AssembledObject.cs
// Author: Ondřej Ondryáš

using System.Globalization;
using System.Text.RegularExpressions;
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
    public string BuildFilePath { get; }
    public bool AssemblySuccessful { get; }

    public bool[]? IsProgramLine { get; }
    public int ProgramLines { get; }

    public Dictionary<uint, string> PossibleDataFields { get; }

    internal AssembledObject(IAsmFile sourceFile, int sourceVersion, string buildFilePath, string objectFilePath,
        string gasOut, string gasErr, bool successful, ILogger<AssembledObject> logger)
    {
        _logger = logger;
        AssemblySuccessful = successful;
        SourceFile = sourceFile;
        SourceVersion = sourceVersion;
        BuildFilePath = buildFilePath;
        ObjectFilePath = objectFilePath;
        AssemblerOutput = gasOut;
        AssemblerErrors = gasErr;
        PossibleDataFields = new Dictionary<uint, string>();

        if (successful)
        {
            IsProgramLine = this.DetermineProgramLines();
            ProgramLines = IsProgramLine.Length;
        }
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

    private static readonly Regex ProgramLineRegex =
        new(@"^\s*(\d+)\s+([0-9a-f]{4,8})\s+[0-9A-F]{2,8}\s*[\w\.:]+", RegexOptions.Compiled);

    private static readonly Regex DataDirectiveRegex = new(
        @"\.(float|single|double|word|long|int|short|hword|byte|ascii|asciz)\s.*",
        RegexOptions.Compiled);

    private bool[] DetermineProgramLines()
    {
        using var reader = new StringReader(AssemblerOutput);
        string? line;

        var linesWithCode = new List<int>();
        var maxLine = 0;

        while ((line = reader.ReadLine()) != null)
        {
            if (line.StartsWith("DEFINED SYMBOLS") || line.StartsWith("NO DEFINED SYMBOLS"))
                break;

            var match = ProgramLineRegex.Match(line);
            if (match.Success)
            {
                var lineNumber = int.Parse(match.Groups[1].Value);
                linesWithCode.Add(lineNumber);
                if (lineNumber > maxLine)
                    maxLine = lineNumber;

                var dataDirectiveMatch = DataDirectiveRegex.Match(line);
                if (dataDirectiveMatch.Success)
                {
                    var address = int.Parse(match.Groups[2].Value, NumberStyles.AllowHexSpecifier);
                    PossibleDataFields[(uint)address] = dataDirectiveMatch.Groups[1].Value;
                }
            }
        }

        var ret = new bool[maxLine];
        foreach (var lineNumber in linesWithCode)
        {
            ret[lineNumber - 1] = true;
        }

        return ret;
    }

    public void Dispose()
    {
        this.DeleteFile();
    }
}
