SET(CMAKE_SYSTEM_NAME Linux)
SET(CMAKE_SYSTEM_PROCESSOR aarch64)

# set the compiler
set(CMAKE_C_COMPILER   aarch64-none-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-none-linux-gnu-g++)

# set the compiler search path
set(CMAKE_FIND_ROOT_PATH $ENV{ROOT_AARCH64})

# adjust the default behaviour of the FIND_XXX() commands:
# search headers and libraries in the target environment, search 
# programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
