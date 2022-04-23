# Debug Adapter Protocol Models

This project contains .NET representations of models used in the [Debug Adapter Protocol](https://microsoft.github.io/debug-adapter-protocol/).

These classes were borrowed from the [OmniSharp.Extensions.DebugAdapter](https://github.com/OmniSharp/csharp-language-server-protocol) project (revision [aacb0ba](https://github.com/OmniSharp/csharp-language-server-protocol/commit/aacb0baddb7c3f0709c6272c76bd176f4f4d698c)) which is licensed under the MIT license as stated below. 

Differences to the original sources:
- JsonRpc-related attributes are removed.
- String enumerations are based on [this StringEnum](https://github.com/gerardog/StringEnum) implementation.
- The root namespace is `Code4Arm.ExecutionCore.Protocol`.
- Changes introduced in newer protocol versions are added (the original project reflects version 1.43.x).

Currently reflects version **1.49.x** of the protocol with the following differences:
- The `restart` request only accepts `LaunchRequestArguments` in its optional `arguments` field.
- Changes introduced in **1.55.X** are also included.

### OmniSharp.Extensions.DebugAdapter License

MIT License

Copyright (c) .NET Foundation and Contributors All Rights Reserved

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### Code4Arm.ExecutionCore.Protocol License

Licensed under the MIT License. The full license text is available in `LICENSE`.

Copyright (c) 2022 Ondřej Ondryáš.
