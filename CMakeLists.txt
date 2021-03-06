cmake_minimum_required( VERSION 2.5 FATAL_ERROR )
project(snetmanmon)

set(TARGET snetmanmon)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.7)
		message(FATAL_ERROR
			"GCC version must be at least 4.7! \nTry: CC=gcc-4.7 CXX=g++-4.7 cmake")
	endif()
endif()

SET(Boost_USE_STATIC_LIBS OFF)
SET(Boost_USE_MULTITHREAD ON)

find_package( Boost 1.49.0 COMPONENTS system regex)
if (NOT Boost_FOUND)
	message (FAtAL_ERROR
		"Boost >= 1.49 is required.\n")
elseif (NOT Boost_SYSTEM_FOUND OR NOT Boost_REGEX_FOUND)
	MESSAGE (FATAL_ERROR ${Boost_ERROR_REASON})
endif()
INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})

add_executable(${TARGET} ${TARGET}.cpp json11/json11.cpp)
target_link_libraries(${TARGET} ${Boost_LIBRARIES})
INSTALL(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${TARGET} DESTINATION bin)

SET_TARGET_PROPERTIES(${TARGET} PROPERTIES
	COMPILE_FLAGS "$ENV{CXXFLAGS} -std=gnu++11 -pthread -pedantic -Wall -Wextra -I."
	LINK_FLAGS "$ENV{LDFLAGS} -pthread -Wl,--as-needed"
)

add_custom_target(version.h
	${CMAKE_CURRENT_SOURCE_DIR}/git-version-gen.sh
	${CMAKE_CURRENT_BINARY_DIR}/version.h
	${CMAKE_CURRENT_SOURCE_DIR}/version
	${CMAKE_CURRENT_SOURCE_DIR})
ADD_DEPENDENCIES(${TARGET} version.h)
SET_SOURCE_FILES_PROPERTIES(${CMAKE_CURRENT_BINARY_DIR}/version.h PROPERTIES GENERATED 1)
SET_SOURCE_FILES_PROPERTIES(${TARGET}.cpp PROPERTIES OBJECT_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/version.h)


add_executable(send_rpc_ra send_rpc_ra.cpp)
SET_TARGET_PROPERTIES(send_rpc_ra PROPERTIES
	COMPILE_FLAGS "$ENV{CXXFLAGS} -std=gnu++11 -pedantic -Wall -Wextra"
	LINK_FLAGS "$ENV{LDFLAGS} -Wl,--as-needed"
)
INSTALL(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/send_rpc_ra DESTINATION sbin)
