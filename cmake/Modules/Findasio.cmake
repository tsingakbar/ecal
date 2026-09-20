# find system-provided asio (header-only)
find_path(asio_INCLUDE_DIR asio.hpp)

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
