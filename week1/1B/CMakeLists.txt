# Cmake 版本
cmake_minimum_required(VERSION 3.13.4)
# set(CMAKE_EXPORT_COMPILE_COMMANDS)
set(CMAKE_BUILD_TYPE DEBUG)
# set(CMAKE_BUILD_SHARED)

# 项目名称
project(1B)

file(GLOB SRC "apps/*.cpp" "src/*.cpp")

# 生成target 1B
add_executable(1B ${SRC})

# 目标include头文件目录
target_include_directories(1B PUBLIC include/ extern/openssl/include/ )
# 目标link库目录
target_link_directories(1B PUBLIC extern/openssl/)

# 目标链接 -lcrypto
target_link_libraries(1B PUBLIC -lcrypto)
