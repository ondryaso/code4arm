// DebuggerSessionHub.cs
// Author: Ondřej Ondryáš

using System.Runtime.CompilerServices;
using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.ExecutionService.HubRequests;
using Code4Arm.ExecutionService.Services;
using MediatR;
using Microsoft.AspNetCore.SignalR;

namespace Code4Arm.ExecutionService.Hubs;

public class DebuggerSessionHub : Hub<IDebuggerSession>
{
    private readonly IMediator _mediator;
    private readonly SessionManager _sessionManager;

    public DebuggerSessionHub(IMediator mediator, SessionManager sessionManager)
    {
        _mediator = mediator;
        _sessionManager = sessionManager;
    }

    private ValueTask<Session> GetSession()
    {
        return _sessionManager.GetSession(Context.ConnectionId);
    }

    private async ValueTask<IExecutionEngine> GetExecution(bool checkLoaded = true,
        [CallerMemberName] string caller = "")
    {
        var session = await this.GetSession();
        var execution = session.GetEngine();

        if (checkLoaded && (execution.State == ExecutionState.Unloaded))
            throw new ExecutableNotLoadedException(null, caller);

        return execution;
    }

    private async ValueTask<IDebugProvider> GetDebugProvider()
    {
        var session = await this.GetSession();
        var execution = session.GetEngine();

        if (execution.DebugProvider == null)
            throw new HubException("No executable loaded.");

        return execution.DebugProvider;
    }

    private async ValueTask<IDebugProtocolSourceLocator> GetSourceLocator()
    {
        var session = await this.GetSession();

        if (session.ProjectSession == null)
            throw new HubException("No project loaded.");

        return await session.ProjectSession.GetSourceLocator();
    }

    public override async Task OnConnectedAsync()
    {
        await _sessionManager.OpenSession(Context.ConnectionId);
        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        await _sessionManager.CloseSession(Context.ConnectionId);
        await base.OnDisconnectedAsync(exception);
    }

    public async Task SetLogLevel(LogLevel level)
    {
        var session = await this.GetSession();
        session.SetRemoteLogLevel(level);
    }

    public async Task<BreakpointLocationsResponse> BreakpointLocations(BreakpointLocationsArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.GetBreakpointLocations(arguments);

        return new BreakpointLocationsResponse() { Breakpoints = new Container<BreakpointLocation>(result) };
    }

    public async Task<ConfigurationDoneResponse> ConfigurationDone(ConfigurationDoneArguments arguments)
    {
        // TODO
        return new ConfigurationDoneResponse();
    }

    public async Task<ContinueResponse> Continue(ContinueArguments arguments)
    {
        var exe = await this.GetExecution();

        Task.Run(async () => await exe.Continue());

        return new ContinueResponse();
    }

    public async Task<DataBreakpointInfoResponse> DataBreakpointInfo(DataBreakpointInfoArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.GetDataBreakpointInfo(arguments);

        return result;
    }

    public async Task<DisassembleResponse> Disassemble(DisassembleArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.Disassemble(arguments);

        return new DisassembleResponse() { Instructions = new Container<DisassembledInstruction>(result) };
    }

    public async Task<DisconnectResponse> Disconnect(DisconnectArguments arguments)
    {
        // TODO
        return new DisconnectResponse();
    }

    public async Task<EvaluateResponse> Evaluate(EvaluateArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.EvaluateExpression(arguments);

        return result;
    }

    public async Task<ExceptionInfoResponse> ExceptionInfo(ExceptionInfoArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.GetLastExceptionInfo();

        return result;
    }

    public async Task<GotoResponse> Goto(GotoArguments arguments)
    {
        // TODO
        var exe = await this.GetExecution();
        await exe.GotoTarget(arguments.TargetId);

        return new GotoResponse();
    }

    public async Task<GotoTargetsResponse> GotoTargets(GotoTargetsArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.GetGotoTargets(arguments);

        return new GotoTargetsResponse() { Targets = new Container<GotoTarget>(result) };
    }

    public async Task<InitializeResponse> Initialize(InitializeRequestArguments arguments)
    {
        var dp = await this.GetDebugProvider();

        return dp.Initialize(arguments);
    }

    public async Task<LaunchResponse> Launch(CustomLaunchArguments arguments)
    {
        var session = await this.GetSession();

        if (arguments.SourceDirectory != null)
        {
            session.InitFromDirectory(arguments.SourceDirectory);
        }
        else if (arguments.SourceFiles != null)
        {
            session.InitFromFiles(arguments.SourceFiles);
        }
        else
        {
            throw new HubException("No build target specified.");
        }

        var exe = await this.GetExecution(false);

        return null!;
    }
    
    public async Task<LoadedSourcesResponse> LoadedSources(LoadedSourcesArguments arguments)
    {
        var sl = await this.GetSourceLocator();

        return new LoadedSourcesResponse() { Sources = new Container<Source>(sl.Sources) };
    }

    public async Task<NextResponse> Next(NextArguments arguments)
    {
        var exe = await this.GetExecution();
        // TODO: handle state
        await exe.Step();

        return new NextResponse();
    }

    public async Task<PauseResponse> Pause(PauseArguments arguments)
    {
        var exe = await this.GetExecution();
        // TODO: handle state

        await exe.Pause();

        return new PauseResponse();
    }

    public async Task<ReadMemoryResponse> ReadMemory(ReadMemoryArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.ReadMemory(arguments);

        return result;
    }

    public async Task<RestartResponse> Restart(RestartArguments arguments)
    {
        var exe = await this.GetExecution();

        // TODO
        Task.Run(async () => await exe.Restart(!(arguments.Arguments?.NoDebug ?? false)));

        return new RestartResponse();
    }

    public async Task<ReverseContinueResponse> ReverseContinue(ReverseContinueArguments arguments)
    {
        var exe = await this.GetExecution();

        // TODO
        Task.Run(async () => await exe.ReverseContinue());

        return new ReverseContinueResponse();
    }

    public async Task<ScopesResponse> Scopes(ScopesArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.MakeVariableScopes();

        return result;
    }

    public async Task<SetBreakpointsResponse> SetBreakpoints(SetBreakpointsArguments arguments)
    {
        if (arguments.Breakpoints is null)
            throw new HubException("Breakpoints must be set. Using lines is not supported.");

        var exe = await this.GetExecution();
        var result = exe.SetBreakpoints(arguments.Source, arguments.Breakpoints);

        return new SetBreakpointsResponse()
            { Breakpoints = new Container<Breakpoint>(result) };
    }

    public async Task<SetDataBreakpointsResponse> SetDataBreakpoints(SetDataBreakpointsArguments arguments)
    {
        var exe = await this.GetExecution();
        var result = exe.SetDataBreakpoints(arguments.Breakpoints);

        return new SetDataBreakpointsResponse()
            { Breakpoints = new Container<Breakpoint>(result) };
    }

    public async Task<SetExceptionBreakpointsResponse> SetExceptionBreakpoints(
        SetExceptionBreakpointsArguments arguments)
    {
        var exe = await this.GetExecution();
        var result = exe.SetExceptionBreakpoints(arguments.Filters);

        return new SetExceptionBreakpointsResponse()
            { Breakpoints = new Container<Breakpoint>(result) };
    }

    public async Task<SetFunctionBreakpointsResponse> SetFunctionBreakpoints(SetFunctionBreakpointsArguments arguments)
    {
        var exe = await this.GetExecution();
        var result = exe.SetFunctionBreakpoints(arguments.Breakpoints);

        return new SetFunctionBreakpointsResponse()
            { Breakpoints = new Container<Breakpoint>(result) };
    }

    public async Task<SetInstructionBreakpointsResponse> SetInstructionBreakpoints(
        SetInstructionBreakpointsArguments arguments)
    {
        var exe = await this.GetExecution();
        var result = exe.SetInstructionBreakpoints(arguments.Breakpoints);

        return new SetInstructionBreakpointsResponse()
            { Breakpoints = new Container<Breakpoint>(result) };
    }

    public async Task<SetVariableResponse> SetVariable(SetVariableArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.SetVariable(arguments);

        return result;
    }

    public async Task<SourceResponse> Source(SourceArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.GetSource(arguments);

        return result;
    }

    public async Task<StackTraceResponse> StackTrace(StackTraceArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.MakeStackTrace();

        return result;
    }

    public async Task<StepBackResponse> StepBack(StepBackArguments arguments)
    {
        var exe = await this.GetExecution();
        await exe.StepBack();

        return new StepBackResponse();
    }

    public async Task<StepInResponse> StepIn(StepInArguments arguments)
    {
        // Behave like Next()
        var exe = await this.GetExecution();
        await exe.Step();

        return new StepInResponse();
    }

    public async Task<StepOutResponse> StepOut(StepOutArguments arguments)
    {
        var exe = await this.GetExecution();
        await exe.StepOut();

        return new StepOutResponse();
    }

    public async Task<TerminateResponse> Terminate(TerminateArguments arguments)
    {
        var exe = await this.GetExecution();
        await exe.Terminate();

        return new TerminateResponse();
    }

    public async Task<VariablesResponse> Variables(VariablesArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.GetChildVariables(arguments);

        return new VariablesResponse()
            { Variables = new Container<Variable>(result) };
    }

    public async Task<WriteMemoryResponse> WriteMemory(WriteMemoryArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.WriteMemory(arguments);

        return result;
    }

    #region Unsupported requests

    public Task<AttachResponse> Attach(AttachRequestArguments arguments)
    {
        throw new InvalidOperationException("Attaching is not supported.");
    }

    public Task<CancelResponse> Cancel(CancelArguments arguments)
    {
        throw new InvalidOperationException("Attaching is not supported.");
    }

    public Task<CompletionsResponse> Completions(CompletionsArguments arguments)
    {
        throw new InvalidOperationException("Completions are not supported.");
    }

    public Task<ModulesResponse> Modules(ModulesArguments arguments)
    {
        throw new InvalidOperationException("Modules are not supported.");
    }

    public Task<RestartFrameResponse> RestartFrame(RestartFrameArguments arguments)
    {
        throw new InvalidOperationException("Restart Frame requests are not supported.");
    }

    public Task<SetExpressionResponse> SetExpression(SetExpressionArguments arguments)
    {
        throw new InvalidOperationException("Set Expression requests are not supported.");
    }

    public Task<StepInTargetsResponse> StepInTargets(StepInTargetsArguments arguments)
    {
        throw new InvalidOperationException("Step In Targets are not supported.");
    }

    public Task<TerminateThreadsResponse> TerminateThreads(TerminateThreadsArguments arguments)
    {
        throw new InvalidOperationException("Threads are not supported.");
    }

    public Task<ThreadsResponse> Threads(ThreadsArguments arguments)
    {
        throw new InvalidOperationException("Threads are not supported.");
    }

    #endregion
}
