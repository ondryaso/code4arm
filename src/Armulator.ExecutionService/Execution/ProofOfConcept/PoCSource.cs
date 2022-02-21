// PoCSource.cs
// Author: Ondřej Ondryáš

using Armulator.ExecutionService.Execution.Abstractions;
using Keystone;

namespace Armulator.ExecutionService.Execution.ProofOfConcept;

public class PoCSource : IProjectSource
{
    private string? _source;
    public string? Source => _source;

    private int[]? _instructionPtrs;
    private int[]? _linePtrs;

    public ReadOnlyMemory<byte>? AssembledCode { get; private set; }
    public ReadOnlyMemory<byte>? AssembledData { get; private set; }

    public int AssembledCodeLength { get; private set; }
    public int AssembledDataLength { get; private set; }

    public int LineToInstruction(int line)
        => _instructionPtrs?[line] ?? throw new InvalidOperationException();

    public int LineToAddress(int line)
        => _instructionPtrs?[line] * 4 ?? throw new InvalidOperationException();

    public int InstructionToLine(int instruction)
    {
        if (_linePtrs is null)
            throw new InvalidOperationException();

        return instruction < _linePtrs.Length ? _linePtrs[instruction] : _linePtrs[^1] + 1;
    }
    
    public int AddressToLine(uint address)
        => this.InstructionToLine((int)(address / 4));

    public void Assemble(string source, ref uint codeAddress, ref uint dataAddress)
    {
        using var ks = new Keystone.Engine(Architecture.ARM, Mode.ARM | Mode.V8 | Mode.LITTLE_ENDIAN)
            { ThrowOnError = true };

        // TODO: Custom symbol resolving
        _source = source;

        var data = ks.Assemble(source, codeAddress);

        this.AssembledData = null;
        this.AssembledDataLength = 0;
        this.AssembledCode = data.Buffer;
        this.AssembledCodeLength = data.Buffer.Length;

        _linePtrs = new int[data.Buffer.Length / 4];

        var instructionPtrs = new List<int>();
        var sr = new StringReader(source);
        string? line;
        var toInsertNext = 0;
        var ip = 0;
        var lc = 0;

        while ((line = sr.ReadLine()) != null)
        {
            line = line.Trim();
            if (line.Length == 0 || line.EndsWith(':'))
            {
                toInsertNext++;
                continue;
            }

            for (var i = 0; i < toInsertNext; i++)
            {
                instructionPtrs.Add(ip);
            }

            instructionPtrs.Add(ip);
            _linePtrs[ip] = lc++;
            ip++;
        }

        _instructionPtrs = instructionPtrs.ToArray();
    }
}
