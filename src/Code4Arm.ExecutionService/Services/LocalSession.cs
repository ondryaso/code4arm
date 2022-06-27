// LocalSession.cs
// Author: Ondřej Ondryáš

using AutoMapper;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionService.Configuration;
using Code4Arm.ExecutionService.Exceptions;
using Code4Arm.ExecutionService.Hubs;
using Code4Arm.ExecutionService.Services.Abstractions;
using Code4Arm.ExecutionService.Services.Projects;
using MediatR;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Options;

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

public class LocalSession : GenericSession
{
    private readonly IFunctionSimulator[] _simulators;

    public LocalSession(ISessionManager manager, string sessionId, IMediator mediator, ILoggerFactory loggerFactory,
        IMapper mapper, IOptionsMonitor<AssemblerOptions> asmOptMon, IOptionsMonitor<LinkerOptions> ldOptMon,
        IOptionsMonitor<ExecutionOptions> exeOptMon, IOptionsMonitor<DebuggerOptions> dbgOptMon,
        IOptionsMonitor<ServiceOptions> serviceOptMon, IEnumerable<IFunctionSimulator> simulators)
        : base(manager, sessionId, mediator, loggerFactory, mapper,
            asmOptMon, ldOptMon, exeOptMon, dbgOptMon, serviceOptMon)
    {
        _simulators = simulators.ToArray();
    }

    private void InitFromDirectory(string path)
    {
        if (Project is DirectoryProjectSession directoryProjectSession)
        {
            if (directoryProjectSession.DirectoryPath == path)
                return;
        }

        Project?.Dispose();
        Project = new DirectoryProjectSession(path, AssemblerOptions, LinkerOptions, _simulators, LoggerFactory);
    }

    private void InitFromFiles(IEnumerable<string> files)
    {
        if (Project is not FilesProjectSession fps)
        {
            Project?.Dispose();
            fps = new FilesProjectSession(SessionId, AssemblerOptions, LinkerOptions, _simulators, LoggerFactory);
            Project = fps;
        }

        fps.UseFiles(files.Select(f => new FilesProjectSession.File(f, f, null)).ToList());
    }

    public override ValueTask<IEnumerable<KeyValuePair<string, int>>> GetTrackedFiles()
    {
        if (Project == null)
            return new ValueTask<IEnumerable<KeyValuePair<string, int>>>(Enumerable.Empty<KeyValuePair<string, int>>());

        return new ValueTask<IEnumerable<KeyValuePair<string, int>>>(
            Project.GetFiles().Select(f => new KeyValuePair<string, int>(f.ClientPath ?? string.Empty, f.Version)));
    }

    protected override Task Init(ISessionLaunchArguments arguments)
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
            throw new NoLaunchTargetException();
        }

        return Task.CompletedTask;
    }
}
