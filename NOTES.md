Building x64 Unicorn for win64:

```
git checkout 88f4eba -- ..\CMakeLists.txt
cmake .. -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release -DUNICORN_ARCH=arm
msbuild unicorn.sln -p:Plaform=x64 -p:Configuration=Release
```

or just replace the MSVC runtime library section in CMakeLists.txt with something like

```
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})
string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
```
