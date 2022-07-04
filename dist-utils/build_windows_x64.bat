call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd publish\unicorn\build-windows-x86_64
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release -DUNICORN_ARCH=arm
msbuild unicorn.sln -p:Platform=x64 -p:Configuration=Release
move Release\unicorn.dll .\
exit