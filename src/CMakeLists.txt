cmake_minimum_required(VERSION 2.6)

# test weather variables from top level directories are missing
IF( NOT CMAKE_BUILD_TYPE )
  MESSAGE(FATAL_ERROR "Do not run cmake on subdirectories")
ENDIF()

add_definitions(-Wall)
add_definitions(-DPROGRAM_NAME=\"${PROJECT_NAME}\")
add_definitions(-DVERSION=\"${E4RAT_VERSION}\")
IF(CMAKE_BUILD_TYPE STREQUAL "release")
    add_definitions(-O2)
    add_definitions(-D_FORTIFY_SOURCE=2)
    add_definitions(-fstack-protector-all)
else(CMAKE_BUILD_TYPE STREQUAL "release")
    add_definitions(-ggdb -DDEBUG_ENABLED)
endif(CMAKE_BUILD_TYPE STREQUAL "release")

SET(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
SET(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/..)
SET(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/..)

##
# Set RPATH to find shared library
##
# use, i.e. don't skip the full RPATH for the build tree
SET(CMAKE_SKIP_BUILD_RPATH  FALSE)

# when building, don't use the install RPATH already
# (but later on when installing)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE) 

SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

# add the automatically determined parts of the RPATH
# which point to directories outside the build tree to the install RPATH
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# the RPATH to be used when installing, but only if it's not a system directory
LIST(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
IF("${isSystemDir}" STREQUAL "-1")
   SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
ENDIF("${isSystemDir}" STREQUAL "-1")

##
# dependencies
##
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

add_library(${PROJECT_NAME}-core SHARED
        config.cc
        logging.cc
        common.cc
        fiemap.cc
        device.cc
    )

target_link_libraries(${PROJECT_NAME}-core
        ${${PROJECT_NAME}_LIBRARIES}
    )

set_target_properties(${PROJECT_NAME}-core  PROPERTIES
        SOVERSION 0
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
        ${PROJECT_NAME}-core
    )
ENDIF(CMAKE_BUILD_TYPE STREQUAL "debug")

foreach( EXE     ${PROJECT_NAME}-collect
                 ${PROJECT_NAME}-realloc 
                 ${PROJECT_NAME}-preload)
    TARGET_LINK_LIBRARIES(${EXE}
        ${${PROJECT_NAME}_LIBRARIES}
        ${PROJECT_NAME}-core
    )
endforeach( EXE )

INSTALL(TARGETS ${PROJECT_NAME}-collect
                ${PROJECT_NAME}-preload
                ${PROJECT_NAME}-realloc
                ${PROJECT_NAME}-core
        RUNTIME DESTINATION "sbin"
        LIBRARY DESTINATION "lib"
        ARCHIVE DESTINATION "lib")

INSTALL(DIRECTORY DESTINATION "/var/lib/${PROJECT_NAME}")
