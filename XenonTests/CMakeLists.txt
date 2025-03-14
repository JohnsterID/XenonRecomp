project("XenonTests")

find_package(GTest REQUIRED)
file(GLOB TEST_FILES *.cpp)

if(TEST_FILES)
    add_executable(XenonTests 
        ${TEST_FILES}
    )
    target_include_directories(XenonTests PRIVATE
        ${CMAKE_SOURCE_DIR}/XenonRecomp
        ${CMAKE_SOURCE_DIR}/XenonAnalyse
        ${CMAKE_SOURCE_DIR}/thirdparty/tomlplusplus/include
        ${CMAKE_SOURCE_DIR}/thirdparty/xxHash
    )
    target_link_libraries(XenonTests 
        PUBLIC 
            XenonUtils
            fmt::fmt
            GTest::GTest
            GTest::Main
    )
    target_compile_options(XenonTests
        PRIVATE 
            "-march=sandybridge"
            "-Wno-unused-label"
            "-Wno-unused-variable"
    )
    include(GoogleTest)
    gtest_discover_tests(XenonTests)
endif()
