// GenericSession.cs
// Author: Ondřej Ondryáš

using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;
using AutoMapper;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.ExecutionService.Configuration;
using Code4Arm.ExecutionService.Exceptions;
using Code4Arm.ExecutionService.Extensions;
using Code4Arm.ExecutionService.Services.Abstractions;
using Code4Arm.ExecutionService.Services.Projects;
using MediatR;
using Microsoft.Extensions.Options;
using ISession = Code4Arm.ExecutionService.Services.Abstractions.ISession;

namespace Code4Arm.ExecutionService.Services;

public abstract class GenericSession : ISession
{
    private readonly ISessionManager _manager;
    private readonly IMediator _mediator;
    protected readonly ILoggerFactory LoggerFactory;
    private readonly IMapper _mapper;
    private readonly ILogger<GenericSession> _logger;
    public event EventHandler<EngineCreatedEventArgs>? EngineCreated;

    private IClientConfiguration? _sessionConfiguration;

    public IClientConfiguration? SessionOptions
    {
        get => _sessionConfiguration;
        set
        {
            _sessionConfiguration = value;
            this.UpdateExecutionOptions(null);
            this.UpdateDebuggerOptions(null);
        }
    }

    public abstract ValueTask<IEnumerable<KeyValuePair<string, int>>> GetTrackedFiles();

    private ISessionLaunchArguments? _lastLaunchArgs;

    private ExecutionEngine? _engine;
    protected IProjectSession? Project;

    protected DebuggerOptions DebuggerOptions;
    protected ExecutionOptions ExecutionOptions;
    protected LinkerOptions LinkerOptions;
    protected AssemblerOptions AssemblerOptions;

    private readonly IDisposable[] _monitorDisposables = new IDisposable[4];

    private readonly IOptionsMonitor<AssemblerOptions> _assemblerOptionsMonitor;
    private readonly IOptionsMonitor<LinkerOptions> _linkerOptionsMonitor;
    private readonly IOptionsMonitor<ExecutionOptions> _executionOptionsMonitor;
    private readonly IOptionsMonitor<DebuggerOptions> _debuggerOptionsMonitor;
    private readonly IOptionsMonitor<ServiceOptions> _serviceOptMon;

    private OptionChangeBehavior _engineOptionsChangeBehavior;

    public GenericSession(ISessionManager manager, string sessionId, IMediator mediator, ILoggerFactory loggerFactory,
        IMapper mapper,
        IOptionsMonitor<AssemblerOptions> asmOptMon, IOptionsMonitor<LinkerOptions> ldOptMon,
        IOptionsMonitor<ExecutionOptions> exeOptMon, IOptionsMonitor<DebuggerOptions> dbgOptMon,
        IOptionsMonitor<ServiceOptions> serviceOptMon)
    {
        _manager = manager;
        _mediator = mediator;
        LoggerFactory = loggerFactory;
        _mapper = mapper;
        _logger = loggerFactory.CreateLogger<GenericSession>();
        SessionId = sessionId;

        _monitorDisposables[0] = asmOptMon.OnChange(_ => this.UpdateAssemblerOptions(null));
        _monitorDisposables[1] = ldOptMon.OnChange(_ => this.UpdateLinkerOptions(null));
        _monitorDisposables[2] = ldOptMon.OnChange(_ => this.UpdateExecutionOptions(null));
        _monitorDisposables[3] = ldOptMon.OnChange(_ => this.UpdateDebuggerOptions(null));

        _assemblerOptionsMonitor = asmOptMon;
        _linkerOptionsMonitor = ldOptMon;
        _executionOptionsMonitor = exeOptMon;
        _debuggerOptionsMonitor = dbgOptMon;
        _serviceOptMon = serviceOptMon;

        AssemblerOptions = _assemblerOptionsMonitor.CurrentValue;
        LinkerOptions = _linkerOptionsMonitor.CurrentValue;
        ExecutionOptions = _executionOptionsMonitor.CurrentValue;
        DebuggerOptions = _debuggerOptionsMonitor.CurrentValue;
    }

    private async Task Log(int code, string message, string description, ConnectionType? targetHint = null)
        => await _manager.Log(SessionId, code, message, description, targetHint);

    public string SessionId { get; }

    public ValueTask<IExecutionEngine> GetEngine()
    {
        if (_engine == null)
            this.RefreshEngine();

        if (_engineOptionsChangeBehavior == OptionChangeBehavior.RecreateEngine
            && _engine.State is ExecutionState.Unloaded or ExecutionState.Finished)
            this.RefreshEngine();

        return ValueTask.FromResult<IExecutionEngine>(_engine);
    }

    public async Task BuildAndLoad(ISessionLaunchArguments arguments)
    {
        await this.Init(arguments);

        var buildResult = await Build();

        this.UpdateExecutionOptions(arguments);
        this.UpdateDebuggerOptions(arguments);

        var exe = await this.GetEngine();

        if (_engineOptionsChangeBehavior == OptionChangeBehavior.ReloadExecutable 
            || exe.ExecutableInfo == null
            || exe.ExecutableInfo != buildResult.Executable)
        {
            await exe.LoadExecutable(buildResult.Executable!);
            _engineOptionsChangeBehavior = OptionChangeBehavior.None;
        }

        _lastLaunchArgs = arguments;

        async Task<MakeResult> Build()
        {
            this.UpdateAssemblerOptions(arguments);
            this.UpdateLinkerOptions(arguments);

            var build = await Project!.Build(false);

            if (build.State == MakeResultState.InvalidObjects)
            {
                if (build.InvalidObjects == null)
                {
                    _logger.LogError("InvalidObjects state but InvalidObjects is null.");

                    throw new DebuggerException(ExceptionCodes.UnexpectedErrorId, ExceptionCodes.UnexpectedError,
                        DebuggerExceptionType.User, "Unexpected execution service error (InvalidObjects null).");
                }

                foreach (var invalidObject in build.InvalidObjects)
                {
                    await this.Log(ExceptionCodes.AssembleId, ExceptionCodes.Assemble,
                        invalidObject.AssemblerErrors + "\n", ConnectionType.Debugger);
                }

                throw new AssemblingException(string.Format(ExceptionMessages.Assembling, build.InvalidObjects?.Count));
            }

            if (build.State == MakeResultState.LinkingError)
            {
                if (build.LinkerError != null)
                    await this.Log(ExceptionCodes.LinkId, ExceptionCodes.Link,
                        build.LinkerError + "\n", ConnectionType.Debugger);

                throw new LinkingException();
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
        arguments ??= _lastLaunchArgs;

        var newOptions = _assemblerOptionsMonitor.CurrentValue with
        {
            GasOptions = arguments?.AssemblerOptions ?? _sessionConfiguration?.AssemblerOptions
            ?? _assemblerOptionsMonitor.CurrentValue.GasOptions
        };

        if (!newOptions.GasOptions.SequenceOrNullEqual(AssemblerOptions.GasOptions))
        {
            this.ValidateAssemblerOptions(newOptions);

            Project?.UseAssemblerOptions(newOptions);
            AssemblerOptions = newOptions;
        }
    }

    private void UpdateLinkerOptions(ISessionLaunchArguments? arguments)
    {
        arguments ??= _lastLaunchArgs;

        var newOptions = _linkerOptionsMonitor.CurrentValue with { };

        if (_sessionConfiguration != null)
            _mapper.Map(_sessionConfiguration, newOptions);

        if (arguments != null)
            _mapper.Map<IClientConfiguration, LinkerOptions>(arguments, newOptions);

        if (!newOptions.LdOptions.SequenceOrNullEqual(LinkerOptions.LdOptions)
            || !newOptions.LdTrailOptions.SequenceOrNullEqual(LinkerOptions.LdTrailOptions)
            || newOptions.TrampolineEndAddress != LinkerOptions.TrampolineEndAddress
            || newOptions.TrampolineStartAddress != LinkerOptions.TrampolineStartAddress)
        {
            this.ValidateLinkerOptions(newOptions);

            Project?.UseLinkerOptions(_linkerOptionsMonitor.CurrentValue);
            LinkerOptions = newOptions;
        }
    }

    private void UpdateExecutionOptions(ISessionLaunchArguments? arguments)
    {
        arguments ??= _lastLaunchArgs;
        var configuredOptions = _mapper.Map<ExecutionOptions>(_executionOptionsMonitor.CurrentValue);

        if (_sessionConfiguration?.ExecutionOptions != null)
            _mapper.Map(_sessionConfiguration.ExecutionOptions, configuredOptions);

        if (arguments?.ExecutionOptions != null)
            _mapper.Map(arguments.ExecutionOptions, configuredOptions);

        this.ValidateExecutionOptions(configuredOptions);

        var compResult = ExecutionOptions.Compare(configuredOptions);
        ExecutionOptions = configuredOptions;
        if (_engine != null)
            _engine.Options = configuredOptions;

        _engineOptionsChangeBehavior = compResult;
    }

    private void UpdateDebuggerOptions(ISessionLaunchArguments? arguments)
    {
        arguments ??= _lastLaunchArgs;
        var configuredOptions = _mapper.Map<DebuggerOptions>(_debuggerOptionsMonitor.CurrentValue);

        try
        {
            if (_sessionConfiguration?.DebuggerOptions != null)
                _mapper.Map(_sessionConfiguration.DebuggerOptions, configuredOptions);

            if (arguments?.DebuggerOptions != null)
                _mapper.Map(arguments.DebuggerOptions, configuredOptions);
        }
        catch (AutoMapperMappingException e)
        {
            if (e.InnerException is ArgumentException)
                throw new LaunchConfigException(ExceptionMessages.LaunchConfigInvalidEncoding);

            _logger.LogWarning(e, "Unexpected mapping exception.");

            throw new LaunchConfigException(ExceptionMessages.LaunchConfig);
        }

        DebuggerOptions = configuredOptions;

        if (_engine != null)
            _engine.DebugProvider.Options = DebuggerOptions;
    }

    private void ValidateAssemblerOptions(AssemblerOptions newOptions)
    {
        var serviceOptions = _serviceOptMon.CurrentValue;
        if (newOptions.GasOptions is { Length: > 0 } && serviceOptions.AllowedAssemblerOptionsRegex != null)
        {
            var optRegex = new Regex(serviceOptions.AllowedAssemblerOptionsRegex);
            foreach (var option in newOptions.GasOptions)
            {
                if (!optRegex.IsMatch(option) &&
                    !(_assemblerOptionsMonitor.CurrentValue.GasOptions?.Contains(option) ?? false))
                    throw new LaunchConfigException(ExceptionMessages.LaunchConfigInvalidAssemblerOption, option);
            }
        }
    }

    private void ValidateLinkerOptions(LinkerOptions newOptions)
    {
        var serviceOptions = _serviceOptMon.CurrentValue;
        if (serviceOptions.AllowedLinkerOptionsRegex != null)
        {
            var optRegex = new Regex(serviceOptions.AllowedLinkerOptionsRegex);

            if (newOptions.LdOptions is { Length: > 0 })
            {
                foreach (var option in newOptions.LdOptions)
                {
                    if (!optRegex.IsMatch(option) &&
                        !(_linkerOptionsMonitor.CurrentValue.LdOptions?.Contains(option) ?? false))
                        throw new LaunchConfigException(ExceptionMessages.LaunchConfigInvalidLinkerOption, option);
                }
            }

            if (newOptions.LdTrailOptions is { Length: > 0 })
            {
                foreach (var option in newOptions.LdTrailOptions)
                {
                    if (!optRegex.IsMatch(option) &&
                        !(_linkerOptionsMonitor.CurrentValue.LdTrailOptions?.Contains(option) ?? false))
                        throw new LaunchConfigException(ExceptionMessages.LaunchConfigInvalidLinkerOption, option);
                }
            }
        }
    }

    private void ValidateExecutionOptions(ExecutionOptions options)
    {
        var serviceOptions = _serviceOptMon.CurrentValue;

        if (options.Timeout < 500)
            throw new LaunchConfigException(ExceptionMessages.LaunchConfigTimeoutTooSmall, 500);

        if (options.Timeout > serviceOptions.ExecutionTimeoutLimit)
            throw new LaunchConfigException(ExceptionMessages.LaunchConfigTimeoutTooBig,
                serviceOptions.ExecutionTimeoutLimit);

        if (options.Timeout == -1 && !serviceOptions.AllowInfiniteExecutionTimeout)
            throw new LaunchConfigException(ExceptionMessages.LaunchConfigInfiniteTimeout);

        if (options.StackSize > serviceOptions.StackSizeLimit)
            throw new LaunchConfigException(ExceptionMessages.LaunchConfigStackSizeTooBig,
                serviceOptions.StackSizeLimit, serviceOptions.StackSizeLimit / 1024);
    }

    [MemberNotNull(nameof(_engine))]
    private void RefreshEngine()
    {
        var old = _engine;
        var oldClientInfo = _engine?.DebugProvider.ClientInfo;

        _engine = new ExecutionEngine(ExecutionOptions, DebuggerOptions, _mediator,
            LoggerFactory.CreateLogger<ExecutionEngine>());

        if (oldClientInfo != null)
            _engine.DebugProvider.Initialize(oldClientInfo);

        _engineOptionsChangeBehavior = OptionChangeBehavior.None;
        this.EngineCreated?.Invoke(this, new EngineCreatedEventArgs(_engine, old));
    }

    protected abstract Task Init(ISessionLaunchArguments arguments);

    public virtual void Dispose()
    {
        _engine?.Dispose();
    }
}
