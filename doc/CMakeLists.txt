cmake_minimum_required(VERSION 2.6)

# test weather variables from top level directories are missing
IF( NOT E4RAT_VERSION )
  MESSAGE(FATAL_ERROR "Do not run cmake on subdirectories")
ENDIF()

ADD_CUSTOM_TARGET(ManPages ALL)

ADD_CUSTOM_COMMAND(
  TARGET ManPages
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/e4rat-collect.pod 
  COMMAND pod2man ARGS e4rat-collect.pod 
  	  	       e4rat-collect.8
  	  	       --section 8
		       --center "User Manuals"
		       --release "e4rat ${E4RAT_VERSION}"
  OUTPUTS ${CMAKE_CURRENT_BINARY_DIR}/e4rat-collect.8
)

ADD_CUSTOM_COMMAND(
  TARGET ManPages 
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/e4rat-realloc.pod 
  COMMAND pod2man ARGS e4rat-realloc.pod
  	  	       e4rat-realloc.8
  	  	       --section 8
		       --center "User Manuals"
		       --release "e4rat ${E4RAT_VERSION}"
  OUTPUTS e4rat-realloc.8
)

ADD_CUSTOM_COMMAND(
  TARGET ManPages 
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/e4rat-preload.pod 
  COMMAND pod2man ARGS e4rat-preload.pod
  	  	       e4rat-preload.8
  	  	       --section 8
		       --center "User Manuals"
		       --release "e4rat ${E4RAT_VERSION}"
  OUTPUTS e4rat-preload.8
)

ADD_CUSTOM_COMMAND(
  TARGET ManPages 
  SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/e4rat.conf.pod 
  COMMAND pod2man ARGS e4rat.conf.pod
  	  	       e4rat.conf.5
  	  	       --section 5
		       --center "User Manuals"
		       --release "e4rat ${E4RAT_VERSION}"
  OUTPUTS e4rat.conf.5
)

ADD_CUSTOM_COMMAND(
  TARGET ManPages
  SOURCE ManPages
  DEPENDS
  	  e4rat-collect.8
	  e4rat-realloc.8
	  e4rat-preload.8
	  e4rat.conf.5
)

INSTALL(FILES
		    e4rat-collect.8 
		    e4rat-realloc.8
		    e4rat-preload.8
	DESTINATION share/man/man8)

INSTALL(FILES
            e4rat.conf.5
    DESTINATION share/man/man5)

