// LocalSession.cs
// Author: Ondřej Ondryáš

using System.ComponentModel.Design;
using System.Diagnostics.CodeAnalysis;
using AutoMapper;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.Debugger;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.ExecutionService.ClientConfiguration;
using Code4Arm.ExecutionService.Configuration;
using Code4Arm.ExecutionService.Hubs;
using Code4Arm.ExecutionService.Services.Abstractions;
using Code4Arm.ExecutionService.Services.Projects;
using MediatR;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Options;
using ISession = Code4Arm.ExecutionService.Services.Abstractions.ISession;

namespace Code4Arm.ExecutionService.Services;

public class LocalSessionManager<TToolHub, TDebuggerHub, TToolHubClient, TDebuggerHubClient>
    : GenericSessionManager<LocalSession, TToolHub, TDebuggerHub, TToolHubClient, TDebuggerHubClient>
    where TToolHub : Hub<TToolHubClient>
    where TDebuggerHub : Hub<TDebuggerHubClient>
    where TToolHubClient : class, ILoggingClient
    where TDebuggerHubClient : class, ILoggingClient
{
    private readonly IServiceProvider _serviceProvider;

    public LocalSessionManager(ILoggerFactory loggerFactory, IServiceProvider serviceProvider,
        IHubContext<TToolHub, TToolHubClient> toolHub, IHubContext<TDebuggerHub, TDebuggerHubClient> debuggerHub)
        : base(toolHub, debuggerHub, loggerFactory)
    {
        _serviceProvider = serviceProvider;
    }

    protected override ValueTask<LocalSession> MakeSession(Guid sessionId)
    {
        var session = ActivatorUtilities.CreateInstance<LocalSession>(_serviceProvider,
            this, sessionId.ToString());

        return ValueTask.FromResult(session);
    }
}

public class LocalSession : ISession
{
    private readonly ISessionManager _manager;
    private readonly IMediator _mediator;
    private readonly ILoggerFactory _loggerFactory;
    private readonly IMapper _mapper;
    private readonly ILogger<LocalSession> _logger;
    public event EventHandler<EngineCreatedEventArgs>? EngineCreated;

    private DebuggerOptionsOverlay? _sessionDebuggerOptions;

    public DebuggerOptionsOverlay? SessionDebuggerOptions
    {
        get => _sessionDebuggerOptions;
        set
        {
            _sessionDebuggerOptions = value;
            this.UpdateDebuggerOptions(null);
        }
    }

    private ExecutionOptionsOverlay? _sessionExecutionOptions;

    public ExecutionOptionsOverlay? SessionExecutionOptions
    {
        get => _sessionExecutionOptions;
        set
        {
            _sessionExecutionOptions = value;
            this.UpdateExecutionOptions(null);
        }
    }

    private ExecutionEngine? _engine;
    private IProjectSession? _project;

    private DebuggerOptions _debuggerOptions = new();
    private ExecutionOptions _executionOptions = new();
    private LinkerOptions _linkerOptions = new();
    private AssemblerOptions _assemblerOptions = new();

    private readonly IDisposable[] _monitorDisposables = new IDisposable[4];

    private readonly IOptionsMonitor<AssemblerOptions> _assemblerOptionsMonitor;
    private readonly IOptionsMonitor<LinkerOptions> _linkerOptionsMonitor;
    private readonly IOptionsMonitor<ExecutionOptions> _executionOptionsMonitor;
    private readonly IOptionsMonitor<DebuggerOptions> _debuggerOptionsMonitor;

    private bool _refreshEngine, _forceRebuild;

    public LocalSession(ISessionManager manager, string sessionId, IMediator mediator, ILoggerFactory loggerFactory,
        IMapper mapper,
        IOptionsMonitor<AssemblerOptions> asmOptMon, IOptionsMonitor<LinkerOptions> ldOptMon,
        IOptionsMonitor<ExecutionOptions> exeOptMon, IOptionsMonitor<DebuggerOptions> dbgOptMon,
        IOptionsMonitor<ServiceOptions> serviceOptMon)
    {
        _manager = manager;
        _mediator = mediator;
        _loggerFactory = loggerFactory;
        _mapper = mapper;
        _logger = loggerFactory.CreateLogger<LocalSession>();
        SessionId = sessionId;

        _monitorDisposables[0] = asmOptMon.OnChange(_ => this.UpdateAssemblerOptions(null));
        _monitorDisposables[1] = ldOptMon.OnChange(_ => this.UpdateLinkerOptions(null));
        _monitorDisposables[2] = ldOptMon.OnChange(_ => this.UpdateExecutionOptions(null));
        _monitorDisposables[3] = ldOptMon.OnChange(_ => this.UpdateDebuggerOptions(null));

        _assemblerOptionsMonitor = asmOptMon;
        _linkerOptionsMonitor = ldOptMon;
        _executionOptionsMonitor = exeOptMon;
        _debuggerOptionsMonitor = dbgOptMon;

        this.UpdateAssemblerOptions(null);
        this.UpdateLinkerOptions(null);
        this.UpdateExecutionOptions(null);
        this.UpdateDebuggerOptions(null);
    }

    private async Task Log(int code, string message, string description, ConnectionType? targetHint = null)
        => await _manager.Log(SessionId, code, message, description, targetHint);

    public string SessionId { get; }

    public ValueTask<IExecutionEngine> GetEngine()
    {
        if (_engine == null)
            this.RefreshEngine();

        if (_refreshEngine && _engine.State is ExecutionState.Unloaded or ExecutionState.Finished)
            this.RefreshEngine();

        return ValueTask.FromResult<IExecutionEngine>(_engine);
    }

    public async Task BuildAndLoad(ISessionLaunchArguments arguments)
    {
        if (arguments.SourceDirectory != null)
        {
            this.InitFromDirectory(arguments.SourceDirectory);
        }
        else if (arguments.SourceFiles != null)
        {
            this.InitFromFiles(arguments.SourceFiles);
        }
        else
        {
            throw new DebuggerException(ExceptionCodes.NoLaunchTargetId, ExceptionCodes.NoLaunchTarget,
                DebuggerExceptionType.User, ExceptionMessages.NoLaunchTarget);
        }

        var buildResult = await Build();

        this.UpdateExecutionOptions(arguments);
        this.UpdateDebuggerOptions(arguments);

        var exe = await this.GetEngine();
        await exe.LoadExecutable(buildResult.Executable!);

        async Task<MakeResult> Build()
        {
            this.UpdateAssemblerOptions(arguments);
            this.UpdateLinkerOptions(arguments);

            var build = await _project!.Build(_forceRebuild);
            _forceRebuild = false;

            if (build.State == MakeResultState.InvalidObjects)
            {
                if (build.InvalidObjects == null)
                {
                    _logger.LogError("InvalidObjects state but InvalidObjects is null.");

                    throw new HubException("Unexpected execution service state (InvalidObjects null).");
                }

                foreach (var invalidObject in build.InvalidObjects)
                {
                    await this.Log(ExceptionCodes.AssembleId, ExceptionCodes.Assemble,
                        invalidObject.AssemblerErrors + "\n", ConnectionType.Debugger);
                }

                throw new DebuggerException(ExceptionCodes.AssembleId, ExceptionCodes.Assemble,
                    DebuggerExceptionType.User,
                    $"Cannot assemble {build.InvalidObjects?.Count} source(s). Check output for error details.");
            }

            if (build.State == MakeResultState.LinkingError)
            {
                if (build.LinkerError != null)
                    await this.Log(ExceptionCodes.LinkId, ExceptionCodes.Link,
                        build.LinkerError + "\n", ConnectionType.Debugger);

                throw new DebuggerException(ExceptionCodes.LinkId, ExceptionCodes.Link,
                    DebuggerExceptionType.User, "Cannot link assembled objects. Check output for more details.");
            }

            if (build.Executable == null)
            {
                _logger.LogError("Build successful but executable is null.");

                throw new DebuggerException(ExceptionCodes.UnexpectedErrorId, ExceptionCodes.UnexpectedError,
                    DebuggerExceptionType.User, "Unexpected execution service error (Executable null).");
            }

            foreach (var validObject in build.ValidObjects)
            {
                if (!string.IsNullOrWhiteSpace(validObject.AssemblerErrors))
                {
                    await this.Log(ExceptionCodes.AssembleId, ExceptionCodes.Assemble,
                        validObject.AssemblerErrors + "\n", ConnectionType.Debugger);
                }
            }

            return build;
        }
    }

    private void UpdateAssemblerOptions(ISessionLaunchArguments? arguments)
    {
        // TODO
        _project?.UseAssemblerOptions(_assemblerOptionsMonitor.CurrentValue);
        _assemblerOptions = _assemblerOptionsMonitor.CurrentValue;
        _forceRebuild = true;
    }

    private void UpdateLinkerOptions(ISessionLaunchArguments? arguments)
    {
        // TODO
        _project?.UseLinkerOptions(_linkerOptionsMonitor.CurrentValue);
        _linkerOptions = _linkerOptionsMonitor.CurrentValue;
        _forceRebuild = true;
    }

    private void UpdateExecutionOptions(ISessionLaunchArguments? arguments)
    {
        // TODO
        _executionOptions = _executionOptionsMonitor.CurrentValue;
        _refreshEngine = true;
    }

    private void UpdateDebuggerOptions(ISessionLaunchArguments? arguments)
    {
        var configuredOptions = _debuggerOptionsMonitor.CurrentValue;

        if (_sessionDebuggerOptions != null)
            _mapper.Map(_sessionDebuggerOptions, configuredOptions);

        if (arguments?.DebuggerOptions != null)
            _mapper.Map(arguments.DebuggerOptions, configuredOptions);

        _debuggerOptions = configuredOptions;

        if (_engine != null)
            _engine.DebugProvider.Options = _debuggerOptions;
    }

    [MemberNotNull(nameof(_engine))]
    private void RefreshEngine()
    {
        var old = _engine;
        var oldClientInfo = _engine?.DebugProvider.ClientInfo;

        _engine = new ExecutionEngine(_executionOptions, _debuggerOptions, _mediator,
            _loggerFactory.CreateLogger<ExecutionEngine>());

        if (oldClientInfo != null)
            _engine.DebugProvider.Initialize(oldClientInfo);

        _refreshEngine = false;
        this.EngineCreated?.Invoke(this, new EngineCreatedEventArgs(_engine, old));
    }

    [MemberNotNull(nameof(_project))]
    private void InitFromDirectory(string path)
    {
        if (_project is DirectoryProjectSession directoryProjectSession)
        {
            if (directoryProjectSession.DirectoryPath == path)
                return;
        }

        _project?.Dispose();
        _project = new DirectoryProjectSession(path, _assemblerOptions, _linkerOptions, _loggerFactory);
    }

    [MemberNotNull(nameof(_project))]
    private void InitFromFiles(IEnumerable<string> files)
    {
        _project?.Dispose();
        _project = new FilesProjectSession(files, null, _assemblerOptions, _linkerOptions, _loggerFactory);
    }

    public void Dispose()
    {
        _engine?.Dispose();
    }
}
