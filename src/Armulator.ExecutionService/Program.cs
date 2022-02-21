using Armulator.ExecutionService.Hubs;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSignalR()
    .AddMessagePackProtocol();

var app = builder.Build();

app.UseRouting();
app.UseEndpoints(endpoints =>
    endpoints.MapHub<PoCProjectHub>(""));

app.Run();
