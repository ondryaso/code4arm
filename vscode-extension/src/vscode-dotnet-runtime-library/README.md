# .NET Runtime and SDK Installation Tools

This directory contains a modified version of the [vscode-dotnet-runtime](https://github.com/dotnet/vscode-dotnet-runtime) library used to install the .NET Runtime.

The only change (except for removing the telemetry code) is that it installs the ASP.NET Core Runtime instead of the base .NET Runtime: line 84 of AcquisitionInvoker.ts is changed from `args = args.concat('-Runtime', 'dotnet');` to ` args = args.concat('-Runtime', 'aspnetcore');`. Unfortunately, the original library/extension doesn't allow to do this (see [#211](https://github.com/dotnet/vscode-dotnet-runtime/issues/211)).

## .NET Foundation

.NET Core for VSCode is a [.NET Foundation](https://www.dotnetfoundation.org/projects) project.

See the [.NET home repo](https://github.com/Microsoft/dotnet) to find other .NET-related projects.

## License

.NET Core (including this repo) is licensed under the MIT license.
