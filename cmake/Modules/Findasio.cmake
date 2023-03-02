# prefer system provided asio unless it's too old
find_path(asio_INCLUDE_DIR asio.hpp)
if (asio_INCLUDE_DIR-NOTFOUND)
    set(asio_INCLUDE_DIR "${ECAL_PROJECT_ROOT}/thirdparty/asio/asio/include")
else()
    # Matches a line of the form:
    #
    # #define ASIO_VERSION XXYYZZ // XX.YY.ZZ
    #
    # with arbitrary whitespace between the tokens
    file(
      STRINGS "${asio_INCLUDE_DIR}/asio/version.hpp" ASIO_VERSION_DEFINE_LINE
      REGEX
        "#define[ \t]+ASIO_VERSION[ \t]+[0-9]+[ \t]+//[ \t]+[0-9]+\.[0-9]+\.[0-9]+[ \t]*"
    )
    # Extracts the dotted version number after the comment as ASIO_VERSION_STRING
    string(REGEX
           REPLACE "#define ASIO_VERSION [0-9]+ // ([0-9]+\.[0-9]+\.[0-9]+)"
                   "\\1" ASIO_VERSION_STRING "${ASIO_VERSION_DEFINE_LINE}"
    )
    if(ASIO_VERSION_STRING VERSION_LESS "1.12.2")
      # system provided asio too old, use the bundled version
      set(asio_INCLUDE_DIR "${ECAL_PROJECT_ROOT}/thirdparty/asio/asio/include")
    endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(asio
  REQUIRED_VARS asio_INCLUDE_DIR)

if(NOT TARGET asio::asio)
  set(asio_INCLUDE_DIRS ${asio_INCLUDE_DIR})
  add_library(asio::asio INTERFACE IMPORTED)
  set_target_properties(asio::asio PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${asio_INCLUDE_DIR}
    INTERFACE_COMPILE_DEFINITIONS ASIO_STANDALONE)
  mark_as_advanced(asio_INCLUDE_DIR)
endif()
