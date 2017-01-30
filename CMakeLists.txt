cmake_minimum_required(VERSION 3.4.1)
project(argon2jni)

option(CLANG_SANITIZE "Use Clang sanitizer (address, undefined)" OFF)

find_package(JNI)

include_directories(src/main/c/phc-winner-argon2/include)

if((${CMAKE_SYSTEM_NAME} STREQUAL "Linux") OR (${CMAKE_SYSTEM_NAME} STREQUAL "Android"))
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -fvisibility=hidden")
    add_definitions(-DA2_VISCTL=1)
    if(CMAKE_C_COMPILER_ID STREQUAL "Clang" AND CLANG_SANITIZE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined")
    endif(CMAKE_C_COMPILER_ID STREQUAL "Clang" AND CLANG_SANITIZE)
endif((${CMAKE_SYSTEM_NAME} STREQUAL "Linux") OR (${CMAKE_SYSTEM_NAME} STREQUAL "Android"))

set(ARGON2_FILES
        src/main/c/phc-winner-argon2/src/argon2.c
        src/main/c/phc-winner-argon2/src/core.c
        src/main/c/phc-winner-argon2/src/blake2/blake2b.c
        src/main/c/phc-winner-argon2/src/thread.c
        src/main/c/phc-winner-argon2/src/encoding.c
        src/main/c/phc-winner-argon2/src/ref.c)

set(SOURCE_FILES
        src/main/c/argon2jni.c)

add_library(argon2jni
        SHARED
        ${SOURCE_FILES}
        ${ARGON2_FILES})

target_link_libraries(argon2jni)
