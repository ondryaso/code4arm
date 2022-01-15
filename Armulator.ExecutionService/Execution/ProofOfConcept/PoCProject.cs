// PoCProject.cs
// Author: Ondřej Ondryáš

using Armulator.ExecutionService.Execution.Abstractions;

namespace Armulator.ExecutionService.Execution.ProofOfConcept;

public class PoCProject : IProject
{
    public Guid Identifier { get; }

    public string? Name { get; set; }

    public DateTime Created { get; set; }
    public DateTime Modified { get; set; }
    public DateTime Accessed { get; set; }

    internal readonly PoCInitialState PoCInitialState;
    public IProjectState InitialState => PoCInitialState;

    internal readonly PoCSource PoCSource;
    public IProjectSource Source => PoCSource;

    public PoCProject(PoCInitialState? initialState = null)
    {
        this.Created = DateTime.Now;
        this.Modified = DateTime.Now;
        this.Accessed = DateTime.Now;
        this.Identifier = Guid.NewGuid();

        PoCInitialState = initialState ?? new PoCInitialState();
        PoCSource = new PoCSource();
    }

    public IExecutionContext InitExecution()
    {
        if (PoCSource.AssembledCodeLength <= 0)
        {
            if (PoCSource.Source == null)
                throw new InvalidOperationException("No source for assembly exists.");

            uint a = 0;
            PoCSource.Assemble(PoCSource.Source, ref a, ref a);
        }

        var ctx = new PoCExecutionContext(this);
        return ctx;
    }
}
