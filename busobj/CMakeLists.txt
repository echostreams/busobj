# CMakeList.txt : CMake project for busobj, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

include(TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)

if(WIN32)
	add_definitions(-D_CRTDBG_MAP_ALLOC)
	add_definitions(-D_DEBUG)
	add_definitions(-DLITTLE_ENDIAN=1234)
	add_definitions(-DBIG_ENDIAN=4321)
	add_definitions(-DPDP_ENDIAN=3412)

	macro(get_win_hex outvar)
		string(REGEX MATCH "^([0-9]+)\\.([0-9]+)" ${outvar} ${CMAKE_SYSTEM_VERSION})
		math(EXPR ${outvar} "(${CMAKE_MATCH_1} << 8) + ${CMAKE_MATCH_2}" OUTPUT_FORMAT HEXADECIMAL)
	endmacro()

	get_win_hex(winver)
	add_compile_definitions(_WIN32_WINNT=${winver})

else()
	# detect WSL
	#CMAKE_SYSTEM_NAME:      Linux
	#CMAKE_SYSTEM:           Linux-4.4.0-19041-Microsoft

	if(CMAKE_SYSTEM_NAME MATCHES "Linux")
		string(FIND ${CMAKE_SYSTEM} "Microsoft" WSL)
		if(WSL EQUAL -1)
			remove_definitions(-DWSL2)
		else()
			add_definitions(-DWSL2)
		endif()
	
	endif()
endif()


if(IS_BIG_ENDIAN)
 message(STATUS "BIG_ENDIAN")
 add_definitions(-DBYTE_ORDER=BIG_ENDIAN)
else()
 message(STATUS "LITTLE_ENDIAN")
 add_definitions(-DBYTE_ORDER=LITTLE_ENDIAN)
endif()
message(STATUS "CMAKE_C_BYTE_ORDER: ${CMAKE_C_BYTE_ORDER}")
message(STATUS "CMAKE_CXX_BYTE_ORDER: ${CMAKE_CXX_BYTE_ORDER}")

include_directories(
	"systemd/src/systemd"
	"systemd/src/libsystemd/sd-bus"
	"systemd/src/libsystemd/sd-id128"
	"systemd/src/basic"
	"systemd/src/fundamental"
	"systemd/src/shared"
)

message(STATUS "--CMAKE_SYSTEM_PROCESSOR: ${CMAKE_SYSTEM_PROCESSOR}")

check_type_size("int" __SIZEOF_INT__)
check_type_size("long" __SIZEOF_LONG__)
check_type_size("size_t" __SIZEOF_SIZE_T__)
check_type_size("void*" __SIZEOF_POINTER__)
check_type_size("long long" __SIZEOF_LONG_LONG__)

message(STATUS "__SIZEOF_INT__       : ${__SIZEOF_INT__}")
message(STATUS "__SIZEOF_LONG__      : ${__SIZEOF_LONG__}")
message(STATUS "__SIZEOF_LONG_LONG__ : ${__SIZEOF_LONG_LONG__}")
message(STATUS "__SIZEOF_SIZE_T__    : ${__SIZEOF_SIZE_T__}")
message(STATUS "__SIZEOF_POINTER__   : ${__SIZEOF_POINTER__}")

add_definitions(-D__SIZEOF_INT__=${__SIZEOF_INT__})
add_definitions(-D__SIZEOF_LONG__=${__SIZEOF_LONG__})
add_definitions(-D__SIZEOF_POINTER__=${__SIZEOF_POINTER__})
add_definitions(-D__SIZEOF_LONG_LONG__=${__SIZEOF_LONG_LONG__})
add_definitions(-D__SIZEOF_SIZE_T__=${__SIZEOF_SIZE_T__})

if(WIN32)

	include_directories("windows")
	include_directories("windows/posix/include")
	
	IF(${CMAKE_SYSTEM_PROCESSOR} MATCHES "AMD64") # for desktop
		add_definitions(-D__x86_64__)
	ENDIF()
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
	add_definitions(-DHAVE_REALLOCARRAY)
	add_definitions(-DHAVE_NAME_TO_HANDLE_AT)
	add_definitions(-DHAVE_STRUCT_STATX)
	add_definitions(-D_GNU_SOURCE)
endif()

add_definitions(-DRELATIVE_SOURCE_PATH="systemd/src")
add_definitions(-DGETTEXT_PACKAGE="systemd")
add_definitions(-DNOBODY_USER_NAME="nobody")
add_definitions(-DNOBODY_GROUP_NAME="nogroup")
add_definitions(-DNOLOGIN="/usr/sbin/nologin")
add_definitions(-DFALLBACK_HOSTNAME="buildroot")
add_definitions(-DDEFAULT_HIERARCHY_NAME="hybrid")
add_definitions(-DSYSTEMD_TEST_DATA="./testdata")
add_definitions(-DSYSTEMD_CATALOG_DIR="./catalog")
add_definitions(-DSYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH="/bin/systemd-tty-ask-password-agent")
add_definitions(-DSYSTEMD_SLOW_TESTS_DEFAULT=0)
add_definitions(-DBUILD_MODE_DEVELOPER)
add_definitions(-DSIZEOF_TIME_T=8)
add_definitions(-DSIZEOF_TIMEX_MEMBER=8)
add_definitions(-DSIZEOF_RLIM_T=8)
add_definitions(-DSIZEOF_DEV_T=8)
add_definitions(-DSIZEOF_INO_T=8)
add_definitions(-D_FILE_OFFSET_BITS=64)
add_definitions(-DGPERF_LEN_TYPE=size_t)

#add_definitions(-DENABLE_DEBUG_HASHMAP)

if(NOT WIN32)
add_library(libsystemd
	"systemd/src/fundamental/string-util-fundamental.c"
	"systemd/src/fundamental/sha256.c"

	"systemd/src/basic/architecture.c"
	"systemd/src/basic/log.c"
	"systemd/src/basic/fileio.c"
	"systemd/src/basic/hashmap.c"
	"systemd/src/basic/ordered-set.c"
	"systemd/src/basic/string-util.c"
	"systemd/src/basic/siphash24.c"
	"systemd/src/basic/hash-funcs.c"
	"systemd/src/basic/fd-util.c"
	"systemd/src/basic/alloc-util.c"
	"systemd/src/basic/path-util.c"
	"systemd/src/basic/process-util.c"
	"systemd/src/basic/proc-cmdline.c"
	"systemd/src/basic/random-util.c"
	"systemd/src/basic/format-util.c"
	"systemd/src/basic/time-util.c"
	"systemd/src/basic/parse-util.c"
	"systemd/src/basic/socket-util.c"
	"systemd/src/basic/terminal-util.c"
	"systemd/src/basic/gunicode.c"
	"systemd/src/basic/mempool.c"
	"systemd/src/basic/extract-word.c"
	"systemd/src/basic/ratelimit.c"
	"systemd/src/basic/syslog-util.c"
	"systemd/src/basic/env-util.c"
	"systemd/src/basic/strv.c"
	"systemd/src/basic/utf8.c"
	"systemd/src/basic/locale-util.c"
	"systemd/src/basic/memory-util.c"
	"systemd/src/basic/errno-list.c"
	"systemd/src/basic/string-table.c"
	"systemd/src/basic/signal-util.c"
	"systemd/src/basic/escape.c"
	"systemd/src/basic/io-util.c"
	"systemd/src/basic/fs-util.c"
	"systemd/src/basic/sync-util.c"
	"systemd/src/basic/hexdecoct.c"
	"systemd/src/basic/memfd-util.c"
	"systemd/src/basic/mkdir.c"
	"systemd/src/basic/tmpfile-util.c"
	"systemd/src/basic/prioq.c"
	"systemd/src/basic/user-util.c"
	"systemd/src/basic/hostname-util.c"
	"systemd/src/basic/sort-util.c"
	"systemd/src/basic/stat-util.c"
	"systemd/src/basic/af-list.c"
	"systemd/src/basic/dirent-util.c"
	"systemd/src/basic/cgroup-util.c"
	"systemd/src/basic/audit-util.c"
	"systemd/src/basic/unit-name.c"
	"systemd/src/basic/capability-util.c"
	"systemd/src/basic/login-util.c"
	"systemd/src/basic/xattr-util.c"
	"systemd/src/basic/bus-label.c"
	"systemd/src/basic/hmac.c"
	"systemd/src/basic/chase-symlinks.c"
	"systemd/src/basic/util.c"
	"systemd/src/basic/namespace-util.c"
	"systemd/src/basic/strxcpyx.c"
	"systemd/src/basic/rlimit-util.c"
	"systemd/src/basic/inotify-util.c"
	"systemd/src/basic/virt.c"
	"systemd/src/basic/glob-util.c"
	"systemd/src/basic/env-file.c"
	"systemd/src/basic/build.c"
	"systemd/src/basic/socket-util.c"
	"systemd/src/basic/sysctl-util.c"
	"systemd/src/basic/glyph-util.c"
	"systemd/src/basic/filesystems.c"
	"systemd/src/basic/os-util.c"
	"systemd/src/basic/cap-list.c"
	"systemd/src/basic/unit-def.c"
	"systemd/src/basic/in-addr-util.c"
	"systemd/src/basic/ether-addr-util.c"
	"systemd/src/basic/conf-files.c"
	"systemd/src/basic/process-util.c"

	"systemd/src/libsystemd/disable-mempool.c"
	"systemd/src/libsystemd/sd-bus/sd-bus.c"
	"systemd/src/libsystemd/sd-bus/bus-internal.c"
	"systemd/src/libsystemd/sd-bus/bus-introspect.c"
	"systemd/src/libsystemd/sd-bus/bus-objects.c"
	"systemd/src/libsystemd/sd-bus/bus-slot.c"
	"systemd/src/libsystemd/sd-bus/bus-signature.c"
	"systemd/src/libsystemd/sd-bus/bus-type.c"
	"systemd/src/libsystemd/sd-bus/bus-error.c"
	"systemd/src/libsystemd/sd-bus/bus-message.c"
	"systemd/src/libsystemd/sd-bus/bus-gvariant.c"
	"systemd/src/libsystemd/sd-bus/bus-kernel.c"
	"systemd/src/libsystemd/sd-bus/bus-match.c"
	"systemd/src/libsystemd/sd-bus/bus-container.c"
	"systemd/src/libsystemd/sd-bus/bus-convenience.c"
	"systemd/src/libsystemd/sd-bus/bus-creds.c"
	"systemd/src/libsystemd/sd-bus/bus-control.c"
	"systemd/src/libsystemd/sd-bus/bus-socket.c"
	"systemd/src/libsystemd/sd-bus/bus-track.c"
	"systemd/src/libsystemd/sd-bus/bus-dump.c"
	"systemd/src/libsystemd/sd-bus/bus-common-errors.c"
	"systemd/src/libsystemd/sd-event/sd-event.c"

	"systemd/src/libsystemd/sd-id128/sd-id128.c"
	"systemd/src/libsystemd/sd-id128/id128-util.c"

	"systemd/src/libsystemd/sd-daemon/sd-daemon.c"

	"systemd/src/shared/json.c"
	"systemd/src/shared/xml.c"
	"systemd/src/shared/format-table.c"
	"systemd/src/shared/parse-argument.c"
	"systemd/src/shared/bus-util.c"
	"systemd/src/shared/pretty-print.c"
	"systemd/src/shared/pager.c"
	"systemd/src/shared/verbs.c"
	"systemd/src/shared/spawn-ask-password-agent.c"
	"systemd/src/shared/spawn-polkit-agent.c"
	"systemd/src/shared/selinux-util.c"
	#"systemd/src/shared/copy.c"

	#"systemd/src/libsystemd/sd-login/sd-login.c"
)

target_compile_definitions(libsystemd PRIVATE FULL_STRV)
target_compile_definitions(libsystemd PRIVATE BUS_CREDS_FULL)

# Add source to this project's executable.
add_executable (busobj 
	"busobj.c"
)

add_executable (sd-event-udp
	"sd-event-udp.c"
)

add_executable (test-bus-server "systemd/src/libsystemd/sd-bus/test-bus-server.c")

add_executable (bus-client "bus-client.c")
add_executable (bus-service "bus-service.c")

target_link_libraries(busobj libsystemd)
target_link_libraries(busobj pthread cap rt)

target_include_directories(sd-event-udp PRIVATE "systemd/src/")
target_link_libraries(sd-event-udp libsystemd)
target_link_libraries(sd-event-udp pthread cap rt)

target_include_directories(bus-client PRIVATE "systemd/src/")
target_link_libraries(bus-client libsystemd)
target_link_libraries(bus-client pthread cap rt)

target_include_directories(bus-service PRIVATE "systemd/src/")
target_link_libraries(bus-service libsystemd)
target_link_libraries(bus-service pthread cap rt)

target_link_libraries(test-bus-server libsystemd pthread cap rt)

else()
	#add bus-service to windows
	add_executable (bus-service "bus-service.c")
	target_include_directories(bus-service PRIVATE "systemd/src/")
	target_link_libraries(bus-service libsystemd-mini ws2_32)
endif()

add_library(libsystemd-mini 
	"systemd/src/libsystemd/sd-bus/bus-objects.c"
	"systemd/src/libsystemd/sd-bus/bus-type.c"
	"systemd/src/libsystemd/sd-bus/bus-internal.c"
	"systemd/src/libsystemd/sd-bus/bus-slot.c"
	"systemd/src/libsystemd/sd-bus/bus-error.c"
	"systemd/src/libsystemd/sd-bus/bus-introspect.c"
	"systemd/src/libsystemd/sd-bus/bus-signature.c"
	"systemd/src/libsystemd/sd-bus/bus-match.c"
	"systemd/src/libsystemd/sd-bus/bus-gvariant.c"
	"systemd/src/libsystemd/sd-bus/bus-convenience.c"
	"systemd/src/libsystemd/sd-bus/bus-kernel.c"
	"systemd/src/libsystemd/sd-bus/bus-control.c"
	#"systemd/src/libsystemd/sd-bus/bus-message.c"
	#"systemd/src/libsystemd/sd-bus/sd-bus.c"
	"systemd/src/libsystemd/sd-bus/bus-dump.c"
	"systemd/src/libsystemd/sd-bus/bus-socket.c"
	"systemd/src/libsystemd/sd-bus/bus-creds.c"
	"systemd/src/libsystemd/sd-bus/bus-track.c"

	"mini/bus-message.c"
	"mini/sd-bus.c"
	"mini/sd-event.c"
	"mini/hashmap.c"
	"mini/fileio.c"
	"mini/path-util.c"
	"mini/log.c"
	"mini/strv.c"
	"mini/randombytes.c"
	"mini/escape.c"
	"mini/string-util.c"
	"mini/time-util.c"
	"mini/locale-util.c"
	"mini/tests.c"
	"mini/fd-util.c"
	"mini/fs-util.c"
	"mini/socket-util.c"
	"mini/user-util.c"
	"mini/process-util.c"

	"systemd/src/basic/errno-list.c"
	"systemd/src/basic/ordered-set.c"
	"systemd/src/basic/siphash24.c"
	"systemd/src/basic/hash-funcs.c"
	"systemd/src/basic/memory-util.c"
	"systemd/src/basic/alloc-util.c"
	"systemd/src/fundamental/string-util-fundamental.c"
	"systemd/src/fundamental/sha256.c"
	"systemd/src/shared/xml.c"
	"systemd/src/basic/hmac.c"
	"systemd/src/basic/glyph-util.c"
	"systemd/src/basic/bus-label.c"
	"systemd/src/basic/utf8.c"
	"systemd/src/basic/gunicode.c"
	"systemd/src/basic/prioq.c"
	"systemd/src/basic/mempool.c"
	"systemd/src/basic/io-util.c"
	"systemd/src/basic/hexdecoct.c"
	"systemd/src/basic/parse-util.c"
	#"systemd/src/basic/socket-util.c"
	#"systemd/src/shared/tests.c"
	"systemd/src/shared/bus-object.c"
	"systemd/src/shared/bus-print-properties.c"
	#"systemd/src/shared/varlink.c"
	"systemd/src/basic/extract-word.c"

	"windows/asprintf.c"
	"windows/strndup.c"
	"windows/getuid.cpp"
	"windows/wepoll/getuid.cpp"
	"windows/mmap.c"
	"windows/win_clock_gettime.c"
	"windows/socket.c"
	"windows/posix.c"
	"windows/wepoll/wepoll.c"
	"windows/poll.c"
	"windows/compat.c"
	"windows/dump_wsaprotocol_info.c"

	"systemd/src/busctl/busctl-introspect.c"

	#"systemd/src/libsystemd/sd-event/sd-event.c"
	"systemd/src/libsystemd/sd-daemon/sd-daemon.c"
	"systemd/src/libsystemd/sd-id128/sd-id128.c"
	"systemd/src/libsystemd/sd-id128/id128-util.c"
)

# Add source to this project's executable.
add_executable (test-vtable 
	"test-vtable.c"
)

add_executable(test-busctl
			   "systemd/src/busctl/test-busctl-introspect.c"
               "systemd/src/busctl/busctl-introspect.c"
               "systemd/src/busctl/busctl-introspect.h")

#add_executable(test-hashmap-plain "systemd/src/test/test-hashmap-plain.c")
add_executable(test-bus-marshal "systemd/src/libsystemd/sd-bus/test-bus-marshal.c")

target_link_libraries(test-vtable libsystemd-mini)
# test CrtDumpMemoryLeaks() on windows
target_compile_definitions(test-vtable PUBLIC "$<$<CONFIG:DEBUG>:_DEBUG>")

target_link_libraries(test-busctl libsystemd-mini)
#target_link_libraries(test-hashmap-plain libsystemd-mini)
target_link_libraries(test-bus-marshal libsystemd-mini)

if(WIN32)
	target_link_libraries(test-vtable ws2_32)
	target_link_libraries(test-busctl ws2_32)
	target_link_libraries(test-bus-marshal ws2_32)
else()
	target_link_libraries(test-vtable pthread rt)
	target_link_libraries(test-busctl pthread rt)
	target_link_libraries(test-bus-marshal pthread rt)
endif()

if(WIN32)
	if(EXISTS "c:/lib/boost_1_78_0")
		set(BOOST_ROOT "c:/lib/boost_1_78_0")
	elseif(EXISTS "d:/lib/boost_1_78_0")
		set(BOOST_ROOT "d:/lib/boost_1_78_0")
	endif()
	set(BOOST_INCLUDEDIR ${BOOST_ROOT})
	set(BOOST_LIBRARYDIR ${BOOST_ROOT}/stage/lib)
	set(Boost_COMPILER "-vc142;-vc143")
	set(Boost_ADDITIONAL_VERSIONS "1.78.0")
	set(Boost_USE_STATIC_LIBS ON)
	set(Boost_USE_MULTITHREAD ON)
	set(Boost_USE_STATIC_RUNTIME OFF)

endif()

find_package (Boost 1.71 REQUIRED COMPONENTS thread chrono coroutine context)
message(STATUS "--Boost_INCLUDE_DIR : ${Boost_INCLUDE_DIR}")
message(STATUS "-- Boost_LIBRARIES: ${Boost_LIBRARIES}")

include_directories (SYSTEM ${Boost_INCLUDE_DIR})
include_directories ("sdbusplus/include")
include_directories ("systemd/src")
add_executable(objmgr objmgr.cpp
	"sdbusplus/src/sdbus.cpp"
	"sdbusplus/src/bus.cpp"
	"sdbusplus/src/exception.cpp"
	"sdbusplus/src/server/interface.cpp"
	"sdbusplus/src/server/transaction.cpp"
	"sdbusplus/src/message/native_types.cpp"
)

add_executable(objpeer objpeer.cpp
	"sdbusplus/src/sdbus.cpp"
	"sdbusplus/src/bus.cpp"
	"sdbusplus/src/exception.cpp"
	"sdbusplus/src/server/interface.cpp"
	"sdbusplus/src/server/transaction.cpp"
	"sdbusplus/src/message/native_types.cpp"
)

target_compile_features(libsystemd-mini PRIVATE cxx_std_20)
target_compile_features(objmgr PRIVATE cxx_std_20)
target_compile_features(objpeer PRIVATE cxx_std_20)
if(MSVC)
	target_compile_definitions(objmgr PRIVATE -D__EXCEPTIONS)
	target_compile_options(objmgr PRIVATE /EHsc /W3)
	target_link_libraries(objmgr ${Boost_LIBRARIES} Boost::thread libsystemd-mini)
	target_compile_definitions(objpeer PRIVATE -D__EXCEPTIONS)
	target_compile_options(objpeer PRIVATE /EHsc /W3)
	target_link_libraries(objpeer ${Boost_LIBRARIES} Boost::thread libsystemd-mini)
else()
	target_link_libraries(objmgr ${Boost_LIBRARIES} Boost::thread libsystemd-mini)
	target_link_libraries(objpeer ${Boost_LIBRARIES} Boost::thread libsystemd-mini)
endif()



add_executable (bus-server "bus-server.c")
target_link_libraries(bus-server libsystemd-mini)
if(WIN32)
	target_link_libraries(bus-server ws2_32 ${CMAKE_CURRENT_SOURCE_DIR}/windows/wsock_trace_x64.lib)
else()
	target_link_libraries(bus-server pthread)
endif()

add_executable(test-socketpair "test/test-socketpair.cpp")
target_link_libraries(test-socketpair libsystemd-mini)
if(WIN32)
	target_link_libraries(test-socketpair ws2_32)
else()
	target_link_libraries(test-socketpair pthread)
endif()

add_executable(busctl "systemd/src/busctl/busctl.c" "systemd/src/busctl/busctl-introspect.c" )
target_link_libraries(busctl libsystemd)
if(WIN32)
	target_link_libraries(busctl ws2_32)
else()
	target_link_libraries(busctl pthread cap rt m)
endif()