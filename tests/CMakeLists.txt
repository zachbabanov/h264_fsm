enable_testing()

include(FetchContent)
FetchContent_Declare(
  catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v2.13.10
)
FetchContent_MakeAvailable(catch2)

add_executable(tests_runner
  test_common.cpp
  test_server_helpers.cpp
  test_player.cpp
  test_encoder.cpp
)

target_include_directories(tests_runner PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(tests_runner PRIVATE Catch2::Catch2)

add_test(NAME unit_tests COMMAND tests_runner)
