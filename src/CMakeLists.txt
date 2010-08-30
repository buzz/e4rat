project(defrag)

cmake_minimum_required(VERSION 2.6)
set(CMAKE_VERBOSE_MAKEFILE              off)

set(${PROJECT_NAME}_MAJOR_VERSION   0)
set(${PROJECT_NAME}_MINOR_VERSION   0)
set(${PROJECT_NAME}_PATCH_LEVEL     1)

set(${PROJECT_NAME}_SOVERSION       0)

set(CMAKE_CXX_FLAGS              "-Wall -ggdb")

set(INSTALL_HEADER_FILES
        )
set (${PROJECT_NAME}_SRC 
        ${${PROJECT_NAME}_SRC}
        main.c
    )


SET(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
SET(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/..)
SET(BINARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/..)

FIND_PACKAGE(ext2fs REQUIRED)
set(${PROJECT_NAME}_LIBRARIES   ${${PROJECT_NAME}_LIBRARIES}
    ${EXT2FS_LIBRARY})

#
# Versioning
#
#set(${PROJECT_NAME}_FULL_VERSION
#    ${${PROJECT_NAME}_MAJOR_VERSION}.${${PROJECT_NAME}_MINOR_VERSION}.${${PROJECT_NAME}_PATCH_LEVEL})
#
#set_target_properties(${PROJECT_NAME}  PROPERTIES
#        VERSION ${${PROJECT_NAME}_FULL_VERSION}
#        SOVERSION ${${PROJECT_NAME}_SOVERSION}
#        )

ADD_EXECUTABLE(${PROJECT_NAME} 
	${${PROJECT_NAME}_SRC}
    )
TARGET_LINK_LIBRARIES(${PROJECT_NAME} 
    ${${PROJECT_NAME}_LIBRARIES}
    )
set_target_properties(${PROJECT_NAME}
	PROPERTIES
	LINK_INTERFACE_LIBRARIES "")
	
FILE(GLOB IdlFiles "*.h")
INSTALL(FILES ${IdlFiles} DESTINATION "include/${PROJECT_NAME}")

foreach(filename ${INSTALL_HEADER_FILES})
    get_filename_component(filename_no_extension ${filename} NAME_WE)
    file(WRITE ${filename_no_extension}
        "/* \n"
        " * This file is part of the CSource Config Library\n"
        " * and was automatically generated.\n"
        " */\n"
        "\n"
        "#include \""
        ${filename}
        "\"\n"
        )
    INSTALL(FILES ${filename_no_extension} DESTINATION "include/${PROJECT_NAME}")
endforeach(filename)
