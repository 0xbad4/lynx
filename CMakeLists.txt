cmake_minimum_required(VERSION 3.28)

project(lynx LANGUAGES CXX)

add_library(lynx INTERFACE)

target_include_directories(lynx
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

include(GNUInstallDirs)

install(
    DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    TARGETS lynx
    EXPORT lynxTargets
)

install(
    EXPORT lynxTargets
    FILE lynxTargets.cmake
    NAMESPACE lynx::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/lynx
)