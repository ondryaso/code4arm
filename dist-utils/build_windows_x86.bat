call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars32.bat"
cd publish\\unicorn\\build-windows-i386
cmake .. -G "Visual Studio 17 2022" -A win32 -DCMAKE_BUILD_TYPE=Release -DUNICORN_ARCH=arm
msbuild unicorn.sln -p:Platform="win32" -p:Configuration=Release
move Release\unicorn.dll .\
exit