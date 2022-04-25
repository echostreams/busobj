# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)

if(WIN32)
	if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
		MESSAGE("-- vcpkg root found")
		set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
			CACHE STRING "")
	else()
		MESSAGE("-- vcpkg root not found")
	endif()
	# try clang on windows
	# Must be called before project call
	#set(CMAKE_GENERATOR_TOOLSET "ClangCL")
	#set(CMAKE_C_COMPILER "%ProgramFiles%/LLVM/bin/clang.exe")
    #set(CMAKE_CXX_COMPILER "%ProgramFiles%/LLVM/bin/clang++.exe") 
    #set(CMAKE_C_COMPILER_ID "Clang") 
    #set(CMAKE_CXX_COMPILER_ID "Clang") 
    #set(CMAKE_SYSTEM_NAME "Generic")
endif()

project ("busobj")

# Include sub-projects.
add_subdirectory ("busobj")
