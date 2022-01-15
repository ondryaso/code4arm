// PoCProjectHub.cs
// Author: Ondřej Ondryáš

using System.Collections.Concurrent;
using Armulator.ExecutionService.Execution.Abstractions;
using Armulator.ExecutionService.Execution.ProofOfConcept;
using Microsoft.AspNetCore.SignalR;

namespace Armulator.ExecutionService.Hubs;

public class PoCProjectHub : Hub<IPoCHubClient>
{
    private static readonly ConcurrentDictionary<Guid, IProject> Projects = new();
    private static readonly ConcurrentDictionary<string, Guid> ConnectionAssignments = new();
    private static readonly ConcurrentDictionary<string, IExecutionContext> Executions = new();

    public Guid CreateProject()
    {
        var p = new PoCProject();
        if (Projects.TryAdd(p.Identifier, p))
        {
            return p.Identifier;
        }
        else
        {
            throw new HubException("Cannot create project.");
        }
    }

    public bool AssignProject(Guid guid)
    {
        return ConnectionAssignments.TryAdd(this.Context.ConnectionId, guid);
    }

    public Guid? GetAssignedProject()
    {
        return ConnectionAssignments.TryGetValue(this.Context.ConnectionId, out var val) ? val : null;
    }

    public bool CloseProject()
    {
        return ConnectionAssignments.TryRemove(this.Context.ConnectionId, out _);
    }

    public void SetSource(string source)
    {
        var project = this.GetProject();
        uint a = 0;
        project.Source.Assemble(source, ref a, ref a);
    }

    public void InitExecution()
    {
        var project = this.GetProject();
        if (Executions.TryRemove(this.Context.ConnectionId, out var previousExecution))
        {
            previousExecution.Dispose();
        }

        var execution = project.InitExecution();
        if (!Executions.TryAdd(this.Context.ConnectionId, execution))
        {
            execution.Dispose();
            throw new HubException("Cannot begin execution.");
        }
    }

    public async Task<ExecutionState> RunUntilBreakpoint()
    {
        var execution = this.GetExecution();
        execution.RunToBreakpoint();
        await this.SendRegisters(execution.Registers);
        return execution.ExecutionState;
    }

    public async Task<ExecutionState> Step()
    {
        var execution = this.GetExecution();
        execution.Step();
        await this.SendRegisters(execution.Registers);
        return execution.ExecutionState;
    }

    public async Task GetRegisters()
    {
        var execution = this.GetExecution();
        await this.SendRegisters(execution.Registers);
    }

    private async Task SendRegisters(IRegisterFile<int> rf)
    {
        var o = new PoCRegisterStatus()
        {
            R0 = rf[0], R1 = rf[1], R2 = rf[2], R3 = rf[3], R4 = rf[4], R5 = rf[5],
            R6 = rf[6], R7 = rf[7], R8 = rf[8], R9 = rf[9], R10 = rf[10], R11 = rf[11],
            R12 = rf[12], SP_R13 = rf[13], LR_R14 = rf[14], PC_R15 = rf[15], CPSR = rf[16]
        };

        await this.Clients.Caller.ReceiveRegisters(o);
    }

    private IProject GetProject()
    {
        var projectId = this.GetAssignedProject();
        if (projectId is null)
            throw new HubException("No project assigned.");

        if (!Projects.TryGetValue(projectId.Value, out var project))
            throw new HubException("Invalid project.");

        return project;
    }

    private IExecutionContext GetExecution()
    {
        return Executions.TryGetValue(this.Context.ConnectionId, out var e)
            ? e
            : throw new HubException("No project is currently being executed.");
    }
}
