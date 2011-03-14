cmake_minimum_required(VERSION 2.6)
set(CMAKE_VERBOSE_MAKEFILE              off)

# test weather variables from top level directories are missing
IF( NOT CMAKE_BUILD_TYPE )
  MESSAGE(FATAL_ERROR "Do not run cmake on subdirectories")
ENDIF()

set(CMAKE_CXX_FLAGS_GLOBAL       "-Wall -Wno-deprecated -DPROGRAM_NAME=\\\"${PROJECT_NAME}\\\" -DVERSION=\\\"${E4RAT_VERSION}\\\"")
set(CMAKE_CXX_FLAGS_RELEASE      "${CMAKE_CXX_FLAGS_GLOBAL} -O2")
set(CMAKE_CXX_FLAGS_DEBUG        "${CMAKE_CXX_FLAGS_GLOBAL} -ggdb -DDEBUG_ENABLED")

SET(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
SET(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR})
SET(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/..)

FIND_PACKAGE(ext2fs REQUIRED)
set(${PROJECT_NAME}_LIBRARIES   ${${PROJECT_NAME}_LIBRARIES}
    ${EXT2FS_LIBRARY})

find_package(blkid REQUIRED)
set(${PROJECT_NAME}_LIBRARIES   ${${PROJECT_NAME}_LIBRARIES}
    ${BLKID_LIBRARY})

find_package(audit REQUIRED)
set(${PROJECT_NAME}_LIBRARIES   ${${PROJECT_NAME}_LIBRARIES}
    ${AUDIT_LIBRARY})

find_package(auparse REQUIRED)
set(${PROJECT_NAME}_LIBRARIES   ${${PROJECT_NAME}_LIBRARIES}
    ${AUPARSE_LIBRARY})

find_package(Threads REQUIRED)
set(${PROJECT_NAME}_LIBRARIES   ${${PROJECT_NAME}_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT})

add_library(${PROJECT_NAME}-base STATIC
        config.cc
        logging.cc
        common.cc
        fiemap.cc
        device.cc
    )
ADD_EXECUTABLE(${PROJECT_NAME}-collect
        e4rat-collect.cc
        fileptr.cc
        listener.cc
        eventcatcher.cc
    )

ADD_EXECUTABLE(${PROJECT_NAME}-preload
        e4rat-preload.cc
    )

ADD_EXECUTABLE(${PROJECT_NAME}-realloc
        e4rat-realloc.cc
        defrag.cc
        buddycache.cc
    )


IF(CMAKE_BUILD_TYPE STREQUAL "debug")
    ADD_EXECUTABLE(${PROJECT_NAME}-offsets
        e4rat-offsets.cc
    )
        
TARGET_LINK_LIBRARIES(${PROJECT_NAME}-offsets
        ${${PROJECT_NAME}_LIBRARIES}
        ${PROJECT_NAME}-base
    )
ENDIF(CMAKE_BUILD_TYPE STREQUAL "debug")

TARGET_LINK_LIBRARIES(${PROJECT_NAME}-collect
    ${${PROJECT_NAME}_LIBRARIES}
    ${PROJECT_NAME}-base
    )
TARGET_LINK_LIBRARIES(${PROJECT_NAME}-preload
    ${${PROJECT_NAME}_LIBRARIES}
    ${PROJECT_NAME}-base
    )
TARGET_LINK_LIBRARIES(${PROJECT_NAME}-realloc
    ${${PROJECT_NAME}_LIBRARIES}
    ${PROJECT_NAME}-base
    )

INSTALL(TARGETS ${PROJECT_NAME}-collect
                ${PROJECT_NAME}-preload
                ${PROJECT_NAME}-realloc
                ${PROJECT_NAME}-base
        RUNTIME DESTINATION "sbin"
        LIBRARY DESTINATION "lib"
        ARCHIVE DESTINATION "lib")

INSTALL(CODE "MAKE_DIRECTORY(\"/var/lib/${PROJECT_NAME}\")")

INSTALL(FILES e4rat.conf
        DESTINATION "/etc")
