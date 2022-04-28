// SessionManager.cs
// Author: Ondřej Ondryáš

using System.Collections.Concurrent;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Execution;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.ExecutionService.Services.Projects;
using MediatR;
using Microsoft.Extensions.Options;

namespace Code4Arm.ExecutionService.Services;

public class Session : IDisposable
{
    internal readonly string ConnectionId;
    private readonly SessionManager _manager;
    private readonly IOptionsMonitor<AssemblerOptions> _assemblerOptions;
    private readonly IOptionsMonitor<LinkerOptions> _linkerOptions;
    private readonly IMediator _mediator;
    private readonly ILoggerFactory _loggerFactory;
    private IProjectSession? _projectSession;
    private ExecutionEngine? _engine;

    private InitializeRequestArguments? _clientInfo;

    internal Session(string connectionId, SessionManager manager, IOptionsMonitor<AssemblerOptions> assemblerOptions,
        IOptionsMonitor<LinkerOptions> linkerOptions, IMediator mediator, ILoggerFactory loggerFactory)
    {
        ConnectionId = connectionId;
        _manager = manager;
        _assemblerOptions = assemblerOptions;
        _linkerOptions = linkerOptions;
        _mediator = mediator;
        _loggerFactory = loggerFactory;
    }

    public InitializeRequestArguments ClientInfo
    {
        get
        {
            if (_clientInfo == null)
                throw new InvalidOperationException();

            return _clientInfo;
        }
        set => _clientInfo = value;
    }

    public void InitFromDirectory(string path)
    {
        if (_projectSession is DirectoryProjectSession directoryProjectSession)
        {
            if (directoryProjectSession.DirectoryPath == path)
                return;
        }

        _projectSession?.Dispose();
        _projectSession = new DirectoryProjectSession(path, _assemblerOptions, _linkerOptions, _loggerFactory);
    }

    public void InitFromFiles(IEnumerable<string> files)
    {
        _projectSession?.Dispose();
        _projectSession = new FilesProjectSession(files, null, _assemblerOptions, _linkerOptions, _loggerFactory);
    }

    public IExecutionEngine GetEngine()
    {
        if (_engine != null)
            return _engine;
        
        var remoteLoggerFactory = _manager.GetRemoteLoggerFactory(ConnectionId);
        var clientLogger = new Logger<ExecutionEngine>(remoteLoggerFactory);

        _engine = new ExecutionEngine(new ExecutionOptions(), _mediator,
            _loggerFactory.CreateLogger<ExecutionEngine>(), clientLogger);

        return _engine;
    }

    public IProjectSession? ProjectSession => _projectSession;

    public void CloseSession()
    {
        _projectSession?.Dispose();
        _manager.CleanupSession(this);
    }

    public void SetRemoteLogLevel(LogLevel level)
    {
        var factory = _manager.GetRemoteLoggerFactory(ConnectionId);
        factory.LogLevel = level;
    }

    public void Dispose()
    {
        _projectSession?.Dispose();
        _engine?.Dispose();
        GC.SuppressFinalize(this);
    }
}

public class SessionManager
{
    private readonly IOptionsMonitor<AssemblerOptions> _assemblerOptions;
    private readonly IOptionsMonitor<LinkerOptions> _linkerOptions;
    private readonly IMediator _mediator;
    private readonly ILoggerFactory _loggerFactory;
    private readonly IServiceProvider _serviceProvider;

    private Session? _currentSession;
    private string? _currentConnectionId;

    private ConcurrentDictionary<string, RemoteLoggerFactory> _loggerFactories = new();

    public SessionManager(
        IOptionsMonitor<AssemblerOptions> assemblerOptions, IOptionsMonitor<LinkerOptions> linkerOptions,
        IMediator mediator, ILoggerFactory loggerFactory, IServiceProvider serviceProvider)
    {
        _assemblerOptions = assemblerOptions;
        _linkerOptions = linkerOptions;
        _mediator = mediator;
        _loggerFactory = loggerFactory;
        _serviceProvider = serviceProvider;
    }

    public Task OpenSession(string connectionId)
    {
        _currentSession = new Session(connectionId, this, _assemblerOptions, _linkerOptions, _mediator, _loggerFactory);
        _currentConnectionId = connectionId;

        return Task.CompletedTask;
    }

    internal RemoteLoggerFactory GetRemoteLoggerFactory(string connectionId)
    {
        var factory =
            _loggerFactories.GetOrAdd(connectionId, key => new RemoteLoggerFactory(connectionId, _serviceProvider));

        return factory;
    }

    public string? GetConnectionId(IExecutionEngine engine)
    {
        return _currentConnectionId;
    }

    public ValueTask<Session> GetSession(string connectionId)
    {
        if (_currentConnectionId != connectionId || _currentSession == null)
            throw new InvalidOperationException();

        return new ValueTask<Session>(_currentSession);
    }

    public Task CloseSession(string connectionId)
    {
        if (_currentConnectionId != connectionId || _currentSession == null)
            return Task.CompletedTask;

        _currentSession.CloseSession();

        return Task.CompletedTask;
    }

    internal void CleanupSession(Session session)
    {
        if (_loggerFactories.TryRemove(session.ConnectionId, out var factory))
            factory.Dispose();

        _currentConnectionId = null;
    }
}
