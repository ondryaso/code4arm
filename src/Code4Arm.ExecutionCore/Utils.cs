// Utils.cs
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
//
// THIS FILE CONTAINS SECTIONS LICENSED UNDER A DIFFERENT LICENSE, Creative Commons Attribution-ShareAlike 4.0.
// THESE SECTIONS ARE MARKED IN THE SOURCE CODE BELOW. 
// THE FULL LICENSE TEXT IS AVAILABLE IN FILE 'COPYING.CCBYSA4' or at https://creativecommons.org/licenses/by-sa/4.0/.


using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;

namespace Code4Arm.ExecutionCore;

public static class Utils
{
    /// <summary>
    /// Returns an absolute path to a file in the SupportFiles directory in the current executing assembly's directory.
    /// </summary>
    public static string GetSupportFile(string fileName)
    {
        var assemblyFile = new Uri(Assembly.GetExecutingAssembly().Location).LocalPath;
        var assemblyDir = Path.GetDirectoryName(assemblyFile);

        if (assemblyDir == null)
            return Path.Combine("SupportFiles", fileName);

        return Path.Combine(assemblyDir, "SupportFiles", fileName);
    }
    
    /* ------ Start of code licensed under CC BY-SA 4.0 (Muhammad Rehan Saeed, Ondřej Ondryáš) ------ */

    /// <summary>
    /// Asynchronously starts a process and reads its stdout and stderr in different threads.
    /// The asynchronous operation terminates when the process has ended and all the data has been read.
    /// </summary>
    /// <param name="startInfo">The <see cref="ProcessStartInfo"/> describing the process to start.
    /// Its <see cref="ProcessStartInfo.RedirectStandardOutput"/> and <see cref="ProcessStartInfo.RedirectStandardError"/>
    /// must be set to true if the corresponding <see cref="TextWriter"/> argument is not null.</param>
    /// <param name="timeout">The maximum time the process may run for, or null for no timeout.</param>
    /// <param name="outputTextWriter">A <see cref="TextWriter"/> to write the stdout to, or null if it isn't redirected.</param>
    /// <param name="errorTextWriter">A <see cref="TextWriter"/> to write the stderr to, or null if it isn't redirected.</param>
    /// <returns>A task that will complete when the process exits and the buffers are read. Its result value is the
    /// exit code of the process.</returns>
    /// <remarks>Original source: https://stackoverflow.com/a/39872058. Original author: Muhammad Rehan Saeed. Modified
    /// by Ondřej Ondryáš. Licensed under CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/).</remarks>
    [SuppressMessage("ReSharper", "AccessToDisposedClosure")]
    public static async Task<int> StartProcess(ProcessStartInfo startInfo, int? timeout = null,
        TextWriter? outputTextWriter = null, TextWriter? errorTextWriter = null)
    {
        using var process = new Process() { StartInfo = startInfo };
        var cancellationTokenSource = timeout.HasValue
            ? new CancellationTokenSource(timeout.Value)
            : new CancellationTokenSource();

        process.Start();

        var tasks = new List<Task>(3) { process.WaitForExitAsync(cancellationTokenSource.Token) };
        if (outputTextWriter != null)
        {
            tasks.Add(ReadAsync(x =>
                {
                    process.OutputDataReceived += x;
                    process.BeginOutputReadLine();
                },
                x => process.OutputDataReceived -= x,
                outputTextWriter,
                cancellationTokenSource.Token));
        }

        if (errorTextWriter != null)
        {
            tasks.Add(ReadAsync(x =>
                {
                    process.ErrorDataReceived += x;
                    process.BeginErrorReadLine();
                },
                x => process.ErrorDataReceived -= x,
                errorTextWriter,
                cancellationTokenSource.Token));
        }

        await Task.WhenAll(tasks);
        cancellationTokenSource.Dispose();

        return process.ExitCode;
    }

    /// <summary>
    /// Reads the data from the specified data received event and writes it to the
    /// <paramref name="textWriter"/>.
    /// </summary>
    /// <param name="addHandler">Adds the event handler.</param>
    /// <param name="removeHandler">Removes the event handler.</param>
    /// <param name="textWriter">The text writer.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <remarks>Original source: https://stackoverflow.com/a/39872058. Original author: Muhammad Rehan Saeed. Modified
    /// by Ondřej Ondryáš. Licensed under CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/).</remarks>
    private static Task ReadAsync(this Action<DataReceivedEventHandler> addHandler, 
        Action<DataReceivedEventHandler> removeHandler, TextWriter textWriter,
        CancellationToken cancellationToken = default)
    {
        var taskCompletionSource = new TaskCompletionSource();

        DataReceivedEventHandler handler = null!;

        handler = (_, e) =>
        {
            if (e.Data == null)
            {
                removeHandler(handler);
                taskCompletionSource.TrySetResult();
            }
            else
            {
                textWriter.WriteLine(e.Data);
            }
        };

        addHandler(handler);

        if (cancellationToken != default)
        {
            cancellationToken.Register(() =>
            {
                removeHandler(handler);
                taskCompletionSource.TrySetCanceled();
            });
        }

        return taskCompletionSource.Task;
    }
    
    /* ------ End of code licensed under CC BY-SA 4.0 ------ */
}
