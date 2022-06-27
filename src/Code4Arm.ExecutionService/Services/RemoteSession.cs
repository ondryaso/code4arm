// RemoteSession.cs
// Author: Ondřej Ondryáš

using AutoMapper;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionService.Configuration;
using Code4Arm.ExecutionService.Files;
using Code4Arm.ExecutionService.Hubs;
using Code4Arm.ExecutionService.Services.Abstractions;
using Code4Arm.ExecutionService.Services.Projects;
using MediatR;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Options;

namespace Code4Arm.ExecutionService.Services;

public class RemoteSessionManager<TToolHub, TDebuggerHub, TToolHubClient, TDebuggerHubClient>
    : GenericSessionManager<RemoteSession, TToolHub, TDebuggerHub, TToolHubClient, TDebuggerHubClient>
    where TToolHub : Hub<TToolHubClient>
    where TDebuggerHub : Hub<TDebuggerHubClient>
    where TToolHubClient : class, ILoggingClient
    where TDebuggerHubClient : class, ILoggingClient
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IOptionsMonitor<ServiceOptions> _serviceOptionsMonitor;

    public RemoteSessionManager(ILoggerFactory loggerFactory, IServiceProvider serviceProvider,
        IOptionsMonitor<ServiceOptions> serviceOptionsMonitor,
        IHubContext<TToolHub, TToolHubClient> toolHub, IHubContext<TDebuggerHub, TDebuggerHubClient> debuggerHub)
        : base(toolHub, debuggerHub, loggerFactory)
    {
        _serviceProvider = serviceProvider;
        _serviceOptionsMonitor = serviceOptionsMonitor;
    }

    protected override ValueTask<RemoteSession> MakeSession(Guid sessionId)
    {
        var dir = _serviceOptionsMonitor.CurrentValue.RemoteFilesStorageDirectory;
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        var projDir = Path.Combine(dir, sessionId.ToString());
        if (Directory.Exists(projDir))
            Directory.Delete(projDir, true);

        Directory.CreateDirectory(projDir);

        var session = ActivatorUtilities.CreateInstance<RemoteSession>(_serviceProvider,
            this, sessionId.ToString(), projDir);

        return ValueTask.FromResult(session);
    }
}

public class RemoteSession : GenericSession
{
    private readonly string _filesDirectory;
    private readonly IFunctionSimulator[] _simulators;
    private FilesProjectSession _projectSession;
    private Dictionary<string, string> _fileNames = new();

    public RemoteSession(ISessionManager manager, string sessionId, string filesDirectory,
        IMediator mediator, ILoggerFactory loggerFactory,
        IMapper mapper, IOptionsMonitor<AssemblerOptions> asmOptMon, IOptionsMonitor<LinkerOptions> ldOptMon,
        IOptionsMonitor<ExecutionOptions> exeOptMon, IOptionsMonitor<DebuggerOptions> dbgOptMon,
        IOptionsMonitor<ServiceOptions> serviceOptMon, IEnumerable<IFunctionSimulator> simulators)
        : base(manager, sessionId, mediator, loggerFactory, mapper,
            asmOptMon, ldOptMon, exeOptMon, dbgOptMon, serviceOptMon)
    {
        _filesDirectory = filesDirectory;
        _simulators = simulators.ToArray();
        _projectSession = new FilesProjectSession(SessionId, AssemblerOptions, LinkerOptions,
            _simulators, LoggerFactory);
        Project = _projectSession;
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
        return Task.CompletedTask;
    }

    public void SetFiles(IEnumerable<RemoteFileMetadata> files)
    {
        var fileNames = new List<FilesProjectSession.File>();
        foreach (var file in files)
        {
            if (_fileNames.TryGetValue(file.Name, out var existing))
            {
                fileNames.Add(new FilesProjectSession.File(file.Name, existing, file.Version));

                continue;
            }

            var newName = Guid.NewGuid().ToString() + ".s";
            newName = Path.Combine(_filesDirectory, newName);

            _fileNames.Add(file.Name, newName);
            fileNames.Add(new FilesProjectSession.File(file.Name, newName, file.Version));
        }

        _projectSession.UseFiles(fileNames);
    }

    public async Task UpdateFile(string name, int version, string text)
    {
        if (_projectSession.GetFile(name) is not LocalAsmFile file)
            return;

        var fs = File.Open(file.FileSystemPath, FileMode.OpenOrCreate, FileAccess.ReadWrite,
            FileShare.None);
        var sw = new StreamWriter(fs);
        await sw.WriteAsync(text);
        await sw.FlushAsync();

        await sw.DisposeAsync();
        await fs.DisposeAsync();
        
        file.Version = version;
    }

    public override void Dispose()
    {
        base.Dispose();
        try
        {
            Directory.Delete(_filesDirectory, true);
        }
        catch (Exception e)
        {
            LoggerFactory.CreateLogger<RemoteSession>().LogWarning(e,
                "Cannot delete remote files storage directory for session {Id}.", SessionId);
        }
    }
}
