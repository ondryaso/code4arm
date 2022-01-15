using System.Text;
using DemoClient;
using Microsoft.AspNetCore.SignalR.Client;

var connection = new HubConnectionBuilder()
    .WithUrl("http://localhost:5181/")
    .WithAutomaticReconnect()
    .Build();

connection.On<RegisterStatus>("ReceiveRegisters", rs => { Console.WriteLine(rs.ToString()); });

Console.WriteLine("Connecting");
await connection.StartAsync();

Console.WriteLine("Creating project");
var project = await connection.InvokeAsync<Guid>("CreateProject");
await connection.InvokeAsync("AssignProject", project);

Console.WriteLine("Enter code:");
var sb = new StringBuilder();

while (true)
{
    var line = Console.ReadLine();
    if (line is null or { Length: 0 })
    {
        break;
    }

    sb.AppendLine(line);
}

Console.WriteLine("Assembling code");
await connection.InvokeAsync("SetSource", sb.ToString());

Console.WriteLine("Executing");
await connection.InvokeAsync("InitExecution");

var ctr = 0;
ExecutionState state;
do
{
    state = await connection.InvokeAsync<ExecutionState>("Step");
    Console.WriteLine($"Instruction #{++ctr} done");
} while (state != ExecutionState.Ended);

Console.WriteLine("Finished");
