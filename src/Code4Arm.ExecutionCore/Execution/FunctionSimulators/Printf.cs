// Printf.cs
// Author: Ondřej Ondryáš

using System.Text;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using UnicornManaged;
using UnicornManaged.Const;

namespace Code4Arm.ExecutionCore.Execution.FunctionSimulators;

public class Printf : IFunctionSimulator
{
    public string Name => "printf";

    public void Run(Unicorn engine)
    {
        // TODO: use emulated memory accessor

        var address = engine.RegRead(Arm.UC_ARM_REG_R0);
        var sb = new StringBuilder();

        var buf = new byte[16];
        while (true)
        {
            engine.MemRead(address, buf);

            var end = buf.Length;
            for (var i = 0; i < buf.Length; i++)
                if (buf[i] == 0)
                    end = i;

            sb.Append(Encoding.UTF8.GetString(buf, 0, end));
            if (end != buf.Length)
                break;

            address += buf.Length;
        }

        Console.WriteLine($"EMULATOR OUTPUT: {sb}");
    }
}
