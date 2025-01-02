cmake_minimum_required(VERSION 3.10)

project(Microkit)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_definitions("-Wall -g")

# 包含项目自己的头文件目录
include_directories(include)

# 添加 nlohmann/json 库
add_subdirectory(third_party/json-3.11.2)
add_subdirectory(third_party/tinyxml2-10.0.0)
add_subdirectory(third_party/ELFIO-Release_3.12)

# 找到 libelf
# find_package(PkgConfig)
# pkg_check_modules(LIBELF REQUIRED libelf)

add_executable(microkit main.cpp)

# 链接 nlohmann/json 库
# target_link_libraries(microkit PRIVATE nlohmann_json::nlohmann_json tinyxml2 ${LIBELF_LIBRARIES} elfio::elfio)
target_link_libraries(microkit PRIVATE nlohmann_json::nlohmann_json tinyxml2 elfio::elfio)
