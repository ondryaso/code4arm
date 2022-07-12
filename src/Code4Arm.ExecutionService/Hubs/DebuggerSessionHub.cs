// DebuggerSessionHub.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Protocol.Events;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.ExecutionService.ClientConfiguration;
using Code4Arm.ExecutionService.HubRequests;
using Code4Arm.ExecutionService.Services.Abstractions;
using Microsoft.AspNetCore.SignalR;
using ISession = Code4Arm.ExecutionService.Services.Abstractions.ISession;
using Thread = Code4Arm.ExecutionCore.Protocol.Models.Thread;

namespace Code4Arm.ExecutionService.Hubs;

public class DebuggerSessionHub<TSession> : Hub<IDebuggerSession> where TSession : ISession
{
    private readonly ISessionManager<TSession> _sessionManager;
    private readonly ILogger<DebuggerSessionHub<TSession>> _logger;

    public DebuggerSessionHub(ISessionManager<TSession> sessionManager,
        ILogger<DebuggerSessionHub<TSession>> logger)
    {
        _sessionManager = sessionManager;
        _logger = logger;
    }

    private async ValueTask<ISession> GetSession()
    {
        var currentId = await _sessionManager.GetSessionId(Context.ConnectionId);

        if (currentId == null)
            throw new HubException("This debugger client is not attached to a session.");

        var session = await _sessionManager.GetSession(currentId);

        if (session == null)
            throw new HubException("This debugger client is not attached to a session.");

        return session;
    }

    private async ValueTask<IExecutionEngine> GetExecution()
    {
        var session = await this.GetSession();
        var execution = await session.GetEngine();

        return execution;
    }

    private async ValueTask<IDebugProvider> GetDebugProvider()
    {
        var session = await this.GetSession();
        var execution = await session.GetEngine();

        if (execution.DebugProvider == null)
            throw new HubException("No executable loaded.");

        return execution.DebugProvider;
    }

    private async ValueTask<IDebugProtocolSourceLocator> GetSourceLocator()
    {
        var session = await this.GetSession();
        var execution = await session.GetEngine();

        return execution.SourceLocator;
    }

    public override async Task OnConnectedAsync()
    {
#if !REMOTE
        var sessionId = await _sessionManager.CreateSession();
        await _sessionManager.AssignConnection(Context.ConnectionId, sessionId, ConnectionType.Tool);
        await _sessionManager.AssignConnection(Context.ConnectionId, sessionId, ConnectionType.Debugger);
#endif
        
        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        await base.OnDisconnectedAsync(exception);
        await _sessionManager.RemoveConnection(Context.ConnectionId);

#if !REMOTE && !DEBUG
        Environment.Exit(0);
#endif
    }

    public async Task<BreakpointLocationsResponse> BreakpointLocations(BreakpointLocationsArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.GetBreakpointLocations(arguments);

        return new BreakpointLocationsResponse() { Breakpoints = new Container<BreakpointLocation>(result) };
    }

    public async Task AttachToSession(string sessionId)
    {
        await _sessionManager.AssignConnection(Context.ConnectionId, sessionId, ConnectionType.Debugger);
    }

    public async Task UseClientConfiguration(ClientToolConfiguration configuration)
    {
        var session = await this.GetSession();
        session.SessionOptions = configuration;
    }
    
    public async Task<ConfigurationDoneResponse> ConfigurationDone(ConfigurationDoneArguments arguments)
    {
        // TODO
        var exe = await this.GetExecution();
        await exe.Launch();

        return new ConfigurationDoneResponse();
    }

    public async Task<ContinueResponse> Continue(ContinueArguments arguments)
    {
        var exe = await this.GetExecution();
        await exe.Continue();

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
        var result = await dp.Disassemble(arguments);

        return new DisassembleResponse() { Instructions = new Container<DisassembledInstruction>(result) };
    }

    public Task<DisconnectResponse> Disconnect(DisconnectArguments arguments)
    {
        // TODO
        return Task.FromResult(new DisconnectResponse());
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
        await _sessionManager.WaitForDebuggerAttachment(Context.ConnectionId);
        
        var session = await this.GetSession();
        await session.BuildAndLoad(arguments);

        var exe = await session.GetEngine();

        await Clients.Caller.HandleEvent(EventNames.Initialized, null);
        await exe.InitLaunch(!arguments.NoDebug);

        return new LaunchResponse();
    }

    public async Task<LoadedSourcesResponse> LoadedSources(LoadedSourcesArguments arguments)
    {
        var sl = await this.GetSourceLocator();
        var sources = await sl.GetSources();

        return new LoadedSourcesResponse() { Sources = new Container<Source>(sources) };
    }

    public async Task<NextResponse> Next(NextArguments arguments)
    {
        var exe = await this.GetExecution();
        await exe.Step();

        return new NextResponse();
    }

    public async Task<PauseResponse> Pause(PauseArguments arguments)
    {
        var exe = await this.GetExecution();
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
        await exe.Restart(!(arguments.Arguments?.NoDebug ?? false));

        return new RestartResponse();
    }

    public async Task<ReverseContinueResponse> ReverseContinue(ReverseContinueArguments arguments)
    {
        var exe = await this.GetExecution();
        await exe.ReverseContinue();

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

    public async Task<SetExpressionResponse> SetExpression(SetExpressionArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = dp.SetExpression(arguments);

        return result;
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
        var result = await exe.SetInstructionBreakpoints(arguments.Breakpoints);

        return new SetInstructionBreakpointsResponse()
            { Breakpoints = new Container<Breakpoint>(result) };
    }

    public async Task<SetVariableResponse> SetVariable(SetVariableArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = await dp.SetVariable(arguments);

        return result;
    }

    public async Task<SourceResponse> Source(SourceArguments arguments)
    {
        var dp = await this.GetSourceLocator();
        var result = await dp.GetSourceContents(arguments);

        return result;
    }

    public async Task<StackTraceResponse> StackTrace(StackTraceArguments arguments)
    {
        var dp = await this.GetDebugProvider();
        var result = await dp.MakeStackTrace();

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

    public Task<ThreadsResponse> Threads(ThreadsArguments arguments)
    {
        return Task.FromResult(new ThreadsResponse()
            { Threads = new Container<Thread>(new Thread() { Id = ExecutionEngine.ThreadId, Name = "Emulated CPU" }) });
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

    public Task<StepInTargetsResponse> StepInTargets(StepInTargetsArguments arguments)
    {
        throw new InvalidOperationException("Step In Targets are not supported.");
    }

    public Task<TerminateThreadsResponse> TerminateThreads(TerminateThreadsArguments arguments)
    {
        throw new InvalidOperationException("Threads are not supported.");
    }

    #endregion
}
