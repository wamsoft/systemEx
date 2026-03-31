set(TPSTUB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../tp_stub CACHE PATH "Path to tp_stub directory")
include(${TPSTUB_DIR}/krkrz.cmake)

krkrz_plugin(systemEx
    SOURCES
        main.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../simplebinder/v2link.cpp
    INCLUDES
        ${CMAKE_CURRENT_SOURCE_DIR}/../simplebinder
)
