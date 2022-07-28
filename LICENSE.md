Copyright © 2022 Ondřej Ondryáš

Zdrojový kód projektu **Code4Arm**, který vznikl jako součást bakalářské práce „Simulace procesoru ARM pro výuku programování v asembleru“, je poskytován pod několika licencemi. Zdrojové soubory obsahují v hlavičce označení příslušné licence.

Většina původního kódu autora je dostupný pod licencí GNU GPL verze 3 nebo pozdější (GPL-3.0-or-later). Úplný text licence je dostupný v souboru `COPYING`. Pokud není v souboru explicitně označena licence, použije se právě tato.

Součástí práce je také převzatý a modifikovaný zdrojový kód, jehož autoři umožňují jeho použití pod různými licencemi. V těchto případech se autor projektu Code4Arm pokusil zachovat původní licenci i pro jím modifikované verze tohoto kódu.

Následuje seznam souborů s převzatým kódem a jejich příslušných licencí:

---

Adresář `src/Code4Arm.ExecutionCore.Dwarf/`: 

Část kódu převzata z projektu [SharpDebug](https://github.com/southpolenator/SharpDebug), dostupná pod licencí MIT viz níže. Celý obsah adresáře je dále dostupný pod licencí MIT, viz soubor `LICENSE` tamtéž.

---

### MIT License

Copyright (c) 2019 Vuk Jovanovic

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

Adresář `src/Code4Arm.ExecutionCode.Protocol/`:

Část kódu převzata z projektu [C# Language Server Protocol](https://github.com/OmniSharp/csharp-language-server-protocol), dostupná pod licencí MIT viz níže. Celý obsah adresáře (pokud není určeno jinak) je dále dostupný pod licencí MIT, viz soubor `LICENSE` tamtéž.

---

### MIT License

Copyright (c) .NET Foundation and Contributors \
All Rights Reserved

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

Soubor `src/Code4Arm.ExecutionCode.Protocol/StringEnum/StringEnum.cs`:

Kód převzat z projektu [StringEnum](https://github.com/gerardog/StringEnum), dostupný pod licencí Unlicense viz níže. Modifikovaný kód je dále dostupný pod stejnou licencí.

---

### Unlicense

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>

---

Soubor `src/Code4Arm.ExecutionCore/Execution/FunctionSimulators/Stdio/Tools.cs`:

Původní kód převzat z článku [A printf implementation in C#](https://www.codeproject.com/Articles/19274/A-printf-implementation-in-C), dostupný pod licencí MIT viz níže. Modifikovaný kód dostupný pod licencí GNU GPL v3.

---

### MIT License

Copyright (c) 2015 Richard Prinz

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

Soubor `src/Code4Arm.ExecutionCore/Utils.cs`:

Část kódu je převzata z kódu [z vlákna na StackOverflow](https://stackoverflow.com/a/39872058), dostupná pod licencí CC BY-SA 4.0 (viz soubor `COPYING.CCBYSA4`). Příslušné části kódu jsou označeny a jsou dále dostupné pod stejnou licencí.

---

Adresář `vscode-extension/src/vscode-dotnet-runtime-library/` a soubor `vscode-extension/src/packageManager/dotnetAcquire.ts`:

Kód převzat z projektu [.NET Runtime and SDK Installation Tools](https://github.com/dotnet/vscode-dotnet-runtime), dostupný pod licencí MIT viz níže. Všechen obsah je dále dostupný pod licencí MIT, viz soubor `vscode-extension/src/vscode-dotnet-runtime-library/License.txt`.

---

### MIT License

Copyright (c) .NET Foundation, Microsoft and Contributors

All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
