// Program.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Protocol.Events;
using Code4Arm.ExecutionCore.Protocol.StringEnum;
using Code4Arm.ExecutionService.Configuration;
using Code4Arm.ExecutionService.Extensions;
using Code4Arm.ExecutionService.Hubs;
using Code4Arm.ExecutionService.Services;
using Code4Arm.ExecutionService.Services.Abstractions;
using MediatR;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<IValidateOptions<AssemblerOptions>, AssemblerOptionsValidator>();

builder.Services.Configure<ServiceOptions>(builder.Configuration.GetSection("Service"));

builder.Services.AddOptions<AssemblerOptions>()
       .Bind(builder.Configuration.GetSection("Service:AssemblerOptions"))
       .ValidateOnStart();

builder.Services.Configure<LinkerOptions>(builder.Configuration.GetSection("Service:LinkerOptions"));
builder.Services.Configure<ExecutionOptions>(builder.Configuration.GetSection("Service:DefaultExecutionOptions"));
builder.Services.Configure<DebuggerOptions>(builder.Configuration.GetSection("Service:DefaultDebuggerOptions"));

builder.Services.AddAutoMapper(typeof(Program));

builder.Services.AddMediatR(typeof(Program));

#if REMOTE
builder.Services.AddProtocolEventHandlers<DebuggerSessionHub<RemoteSession>>(typeof(IProtocolEvent));

builder.Services.AddSingleton<ISessionManager<RemoteSession>,
    RemoteSessionManager<DebuggerSessionHub<RemoteSession>,
        DebuggerSessionHub<RemoteSession>,
        IDebuggerSession,
        IDebuggerSession>>();

builder.Services.AddSingleton<ISessionManager>(provider =>
    provider.GetRequiredService<ISessionManager<RemoteSession>>());

builder.Services.AddHostedService<ConnectionClearingBackgroundService>();
#else
builder.Services.AddProtocolEventHandlers<DebuggerSessionHub<LocalSession>>(typeof(IProtocolEvent));

builder.Services.AddSingleton<ISessionManager<LocalSession>,
    LocalSessionManager<DebuggerSessionHub<LocalSession>,
        DebuggerSessionHub<LocalSession>,
        IDebuggerSession,
        IDebuggerSession>>();

builder.Services.AddSingleton<ISessionManager>(provider =>
    provider.GetRequiredService<ISessionManager<LocalSession>>());
#endif

builder.Services.AddSingleton<DebuggerSessionHubResponseFilter>();
builder.Services.AddFunctionSimulators();

builder.Services.AddSignalR(o => { o.EnableDetailedErrors = true; })
#if REMOTE
       .AddHubOptions<DebuggerSessionHub<RemoteSession>>(o =>
#else
       .AddHubOptions<DebuggerSessionHub<LocalSession>>(o =>
#endif
       {
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
app.UseEndpoints(endpoints =>
{
#if REMOTE
    endpoints.MapHub<DebuggerSessionHub<RemoteSession>>("debuggerSession");
    endpoints.MapHub<ToolSessionHub>("toolSession");
#else
    endpoints.MapHub<DebuggerSessionHub<LocalSession>>("debuggerSession");
#endif
});

app.Run();
