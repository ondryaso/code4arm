#define USE_SOCKETS

using System.Net;
using System.Net.Sockets;
using Armfors.LanguageServer.Handlers;
using Armfors.LanguageServer.Services;
using Armfors.LanguageServer.Services.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OmniSharp.Extensions.LanguageServer.Server;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .Enrich.FromLogContext()
#if USE_SOCKETS
    .WriteTo.Console()
#else
    .WriteTo.Debug()
#endif
    .MinimumLevel.Verbose()
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
        .WithHandler<TextDocumentSyncHandler>();
}).ConfigureAwait(false);

await languageServer.WaitForExit.ConfigureAwait(false);

#if USE_SOCKETS
tcpConnection.Close();
tcpServer.Stop();
#endif

static void ConfigureServices(IServiceCollection services)
{
    services.AddLogging();
    services.AddScoped<ISourceStore, FileSourceStore>();
}
