using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Protocol.Events;
using Code4Arm.ExecutionCore.Protocol.StringEnum;
using Code4Arm.ExecutionService.Extensions;
using Code4Arm.ExecutionService.Hubs;
using Code4Arm.ExecutionService.Services;
using MediatR;
using Microsoft.AspNetCore.SignalR;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<AssemblerOptions>(options =>
{
    // TODO
    options.GasPath = "/home/ondryaso/Projects/bp/gcc-arm-none-linux-gnueabihf/bin/arm-none-linux-gnueabihf-as";
});

builder.Services.Configure<LinkerOptions>(options =>
{
    // TODO
    options.LdPath = "/home/ondryaso/Projects/bp/gcc-arm-none-linux-gnueabihf/bin/arm-none-linux-gnueabihf-ld";
});

builder.Services.AddMediatR(typeof(Program));

builder.Services.AddLogHandlers();
builder.Services.AddProtocolEventHandlers(typeof(IProtocolEvent));
builder.Services.AddSingleton<SessionManager>();
builder.Services.AddSingleton<DebuggerSessionHubResponseFilter>();

builder.Services.AddSignalR(o =>
       {
           o.EnableDetailedErrors = true;
           o.AddFilter(typeof(DebuggerSessionHubResponseFilter));
       })
       .AddNewtonsoftJsonProtocol(options =>
       {
           options.PayloadSerializerSettings = new JsonSerializerSettings()
           {
               Converters = new List<JsonConverter>() { new StringEnumJsonConverter() },
               NullValueHandling = NullValueHandling.Ignore,
               ContractResolver = new DefaultContractResolver() { NamingStrategy = new CamelCaseNamingStrategy() }
           };
       })
       .AddMessagePackProtocol();

builder.Services.AddCors();

var app = builder.Build();

app.UseCors(b => b.AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials()
                  .WithOrigins("https://gourav-d.github.io"));

app.UseRouting();
app.UseEndpoints(endpoints => { endpoints.MapHub<DebuggerSessionHub>("debuggerSession"); });

app.Run();
