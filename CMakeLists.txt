cmake_minimum_required(VERSION 2.6)

set(CMAKE_VERBOSE_MAKEFILE              off)

PROJECT(e4rat)

set(E4RAT_VERSION   "0.1.5")

IF( NOT CMAKE_BUILD_TYPE )
    SET( CMAKE_BUILD_TYPE "debug" )
ENDIF()

set(Boost_USE_MULTITHREADED OFF)
add_definitions(-DBOOST_FILESYSTEM_VERSION=2)
find_package(Boost 1.41 COMPONENTS system filesystem regex REQUIRED)
set(${PROJECT_NAME}_LIBRARIES   ${${PROJECT_NAME}_LIBRARIES}
    ${Boost_LIBRARIES})
set(Boost_VERSION_STR  "${Boost_MAJOR_VERSION}.${Boost_MINOR_VERSION}.${Boost_SUBMINOR_VERSION}")

add_subdirectory(   ${CMAKE_CURRENT_SOURCE_DIR}/src)
add_subdirectory(   ${CMAKE_CURRENT_SOURCE_DIR}/doc)


# to generate debian package run: make package

set(ARCH  ${CMAKE_SYSTEM_PROCESSOR})
SET (CPACK_GENERATOR DEB)
IF(CMAKE_SIZEOF_VOID_P MATCHES 4)
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        message("Detected ARCH mismatch: Running x86_64 Kernel on 32-Bit environment")
        set(ARCH "unknown")
    endif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
ENDIF(CMAKE_SIZEOF_VOID_P MATCHES 4)

SET(CPACK_PACKAGE_VERSION  ${E4RAT_VERSION})
SET(CPACK_PACKAGE_FILE_NAME
    "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}-${ARCH}-${CMAKE_BUILD_TYPE}")

SET (CPACK_PACKAGE_CONTACT "Andreas Rid <conso@rz.fh-augsburg.de>")
SET (CPACK_PACKAGE_DESCRIPTION_SUMMARY
        "Reduce disk access time on ext4 filesystems through relevant file defragmentation.")
#SET (CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/ReadMe.txt")
SET (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
SET (CPACK_DEBIAN_PACKAGE_SECTION "extra")
SET (CPACK_DEBIAN_PACKAGE_MAINTAINER "Andreas Rid")
set (CPACK_SET_DESTDIR                  "ON") # Necessary because of the absolute install paths

# extra install and uninstall create subfolders
# I don't know why cpack deb does not create or remove directories.
set( CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
        "${CMAKE_CURRENT_SOURCE_DIR}/debian/preinst"
        "${CMAKE_CURRENT_SOURCE_DIR}/debian/postrm")

SET (CPACK_INSTALL_PREFIX "/usr")

SET (CPACK_DEBIAN_PACKAGE_DEPENDS
        "libboost-filesystem${Boost_VERSION_STR} (>=1.41)")

SET (CPACK_DEBIAN_PACKAGE_DEPENDS
        "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libboost-regex${Boost_VERSION_STR} (>=1.41)")

SET (CPACK_DEBIAN_PACKAGE_DEPENDS
        "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libaudit0 (>=0.1.7)")

SET (CPACK_DEBIAN_PACKAGE_DEPENDS
        "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libblkid1")

SET (CPACK_DEBIAN_PACKAGE_DEPENDS
        "${CPACK_DEBIAN_PACKAGE_DEPENDS}, e2fslibs (>=1.41)")

SET (CPACK_DEBIAN_PACKAGE_CONFLICTS
        auditd)

INCLUDE(CPack)


add_custom_target(src
        COMMAND test -e ${PROJECT_NAME}-${E4RAT_VERSION} || mkdir ${PROJECT_NAME}-${E4RAT_VERSION}
        COMMAND rsync -p --relative `git ls-files` ${PROJECT_NAME}-${E4RAT_VERSION}
        COMMAND tar pczf ${PROJECT_NAME}-${E4RAT_VERSION}-src.tar.gz ${PROJECT_NAME}-${E4RAT_VERSION}
        )


INSTALL(FILES e4rat.conf.sample
        DESTINATION "/etc"
        RENAME e4rat.conf
        )
