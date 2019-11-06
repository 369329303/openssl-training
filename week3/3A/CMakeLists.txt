# Cmake 版本
cmake_minimum_required(VERSION 3.13.4)
# set(CMAKE_EXPORT_COMPILE_COMMANDS)
set(CMAKE_BUILD_TYPE DEBUG)
# set(CMAKE_BUILD_SHARED)

# 项目名称
project(3A)

# apps/ 和 src/ 下的所有源文件
file(GLOB SRC "apps/*.c" "src/*.c")

# 生成target 3A
add_executable(3A ${SRC})

# 目标include头文件目录
target_include_directories(3A PUBLIC include/ extern/openssl/include/ )
# 目标link库目录
target_link_directories(3A PUBLIC extern/openssl/)

# 目标链接 -lcrypto
target_link_libraries(3A PUBLIC -lcrypto)
