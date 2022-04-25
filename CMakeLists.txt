# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)

if(WIN32)
	message(STATUS "PATH: $ENV{PATH}")
	message(STATUS "VCPKG_ROOT: $ENV{VCPKG_ROOT}")
	set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
			CACHE STRING "")
	message(STATUS "CMAKE_TOOLCHAIN_FILE: ${CMAKE_TOOLCHAIN_FILE}")
	
	# try clang on windows
	# Must be called before project call
	if(EXISTS "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin/clang-cl.exe")
		set(LLVM_PATH "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin")
	elseif(EXISTS "C:/Program Files (x86)/Microsoft Visual Studio/2019/Enterprise/VC/Tools/Llvm/x64/bin/clang-cl.exe")
		set(LLVM_PATH "C:/Program Files (x86)/Microsoft Visual Studio/2019/Enterprise/VC/Tools/Llvm/x64/bin")
	endif()
	set(CMAKE_C_COMPILER "${LLVM_PATH}/clang-cl.exe")
    set(CMAKE_CXX_COMPILER "${LLVM_PATH}/clang-cl.exe") 
	set(CMAKE_LINKER "${LLVM_PATH}/lld-link.exe")
    #set(CMAKE_C_COMPILER_ID "Clang") 
    #set(CMAKE_CXX_COMPILER_ID "Clang") 

endif()

project ("busobj")

# Include sub-projects.
add_subdirectory ("busobj")
