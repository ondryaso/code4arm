#define USE_SOCKETS

using System.IO.Abstractions;
using System.Net;
using System.Net.Sockets;
using Armfors.LanguageServer.CodeAnalysis;
using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.Handlers;
using Armfors.LanguageServer.Services;
using Armfors.LanguageServer.Services.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Server;
using Serilog;
using Serilog.Events;

Log.Logger = new LoggerConfiguration()
    .Enrich.FromLogContext()
#if USE_SOCKETS
    .WriteTo.Console()
#else
    .WriteTo.Debug()
#endif
    .MinimumLevel.Verbose()
    .MinimumLevel.Override("OmniSharp", LogEventLevel.Warning)
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
        .WithOutput(networkStream);
#else
    options.WithInput(Console.OpenStandardInput())
        .WithOutput(Console.OpenStandardOutput());
#endif

    options.ConfigureLogging(logBuilder => logBuilder
            .AddSerilog(Log.Logger)
            .AddLanguageProtocolLogging()
            .SetMinimumLevel(LogLevel.Information))
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
    services.AddSingleton(Mock.Of<ITokenizer>());
    services.AddSingleton<IFileSystem, FileSystem>();
    services.AddSingleton<ISourceStore, FileSourceStore>();
    services.AddSingleton<InstructionProvider>();
    services.AddSingleton<ILocalizationService, InlineLocalizationService>();
    services.AddSingleton<IDocumentationProvider, DummyDocumentationProvider>();
    services.AddSingleton<IInstructionProvider>(i => i.GetService<InstructionProvider>());
    services.AddSingleton<IOperandAnalyserProvider>(i => i.GetService<InstructionProvider>());
    services.AddSingleton<IInstructionValidatorProvider>(i => i.GetService<InstructionProvider>());
    services.AddSingleton<IDirectiveAnalyser, DirectiveAnalyser>();
    services.AddSingleton<IDiagnosticsPublisher, DiagnosticsPublisher>();
    services.AddSingleton<ISourceAnalyserStore, SourceAnalyserStore>();
    services.AddSingleton<ITokenizer, Tokenizer>();
}
