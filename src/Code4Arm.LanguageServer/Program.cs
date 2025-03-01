﻿#define USE_SOCKETS

using System.IO.Abstractions;
using System.Net;
using System.Net.Sockets;
using Code4Arm.LanguageServer.CodeAnalysis;
using Code4Arm.LanguageServer.CodeAnalysis.Abstractions;
using Code4Arm.LanguageServer.Handlers;
using Code4Arm.LanguageServer.Services;
using Code4Arm.LanguageServer.Services.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Workspace;
using OmniSharp.Extensions.LanguageServer.Server;
using Serilog;
using Serilog.Events;
using Constants = Code4Arm.LanguageServer.Constants;

Log.Logger = new LoggerConfiguration()
             .Enrich.FromLogContext()
#if USE_SOCKETS
             .WriteTo.Console()
#else
    .WriteTo.Debug()
#endif
             .MinimumLevel.Verbose()
             .MinimumLevel.Override("OmniSharp", LogEventLevel.Debug)
             .CreateLogger();

#if USE_SOCKETS
Log.Information("Accepting client");
var tcpServer = new TcpListener(IPAddress.Any, 5057);
tcpServer.Start();
var tcpConnection = await tcpServer.AcceptTcpClientAsync();
var networkStream = tcpConnection.GetStream();
#endif

var languageServer = await LanguageServer.From(options =>
{
#if USE_SOCKETS
    options.WithInput(networkStream)
        .WithOutput(networkStream)
        .RegisterForDisposal(tcpConnection);
#else
    options.WithInput(Console.OpenStandardInput())
        .WithOutput(Console.OpenStandardOutput());
#endif


    options.ConfigureLogging(logBuilder => logBuilder
            .AddSerilog(Log.Logger)
            .AddLanguageProtocolLogging()
            .SetMinimumLevel(LogLevel.Trace))
        .WithConfigurationSection("code4arm")
        .WithConfigurationSection(Constants.ConfigurationSectionRoot)
        .WithServices(ConfigureServices)
        .WithHandler<TextDocumentSyncHandler>()
        .WithHandler<SemanticTokensHandler>()
        .WithHandler<CompletionHandler>()
        .WithHandler<SignatureHelpHandler>()
        .WithHandler<DocumentSymbolsHandler>()
        .WithHandler<SymbolReferencesHandler>()
        .WithHandler<DefinitionHandler>()
        .WithHandler<FoldingRangesHandler>()
        .WithHandler<CodeLensHandler>();
}).ConfigureAwait(false);

await languageServer.WaitForExit.ConfigureAwait(false);

#if USE_SOCKETS
tcpConnection.Close();
tcpServer.Stop();
#endif

static void ConfigureServices(IServiceCollection services)
{
    services.AddLogging();

    services.AddSingleton(new ConfigurationItem() {Section = "code4arm.editor"});
    services.Configure<LanguageServerOptions>("code4arm.editor");

    services.AddSingleton(Mock.Of<ITokenizer>());
    services.AddSingleton<IFileSystem, FileSystem>();
    services.AddSingleton<ISourceStore, FileSourceStore>();
    services.AddSingleton<InstructionProvider>();
    services.AddSingleton<ILocalizationService, InlineLocalizationService>();
    services.AddSingleton<ISymbolDocumentationProvider, DummyDocumentationProvider>();
    services.AddSingleton<IInstructionProvider>(i => i.GetService<InstructionProvider>());
    services.AddSingleton<IOperandAnalyserProvider>(i => i.GetService<InstructionProvider>());
    services.AddSingleton<IInstructionValidatorProvider>(i => i.GetService<InstructionProvider>());
    services.AddSingleton<IInstructionDocumentationProvider>(i => i.GetService<InstructionProvider>());
    services.AddSingleton<IDirectiveAnalyser, DirectiveAnalyser>();
    services.AddSingleton<IDiagnosticsPublisher, DiagnosticsPublisher>();
    services.AddSingleton<ISourceAnalyserStore, SourceAnalyserStore>();
    services.AddSingleton<ITokenizer, Tokenizer>();
}