# Cmake 版本
cmake_minimum_required(VERSION 3.13.4)
# set(CMAKE_EXPORT_COMPILE_COMMANDS)
set(CMAKE_BUILD_TYPE DEBUG)
# set(CMAKE_BUILD_SHARED)

# 项目名称
project(1A)

# 生成target 1A
add_executable(1A
  apps/main.c
  src/encrypt.c
  src/digest.c
  src/helper.c
  src/my_hmac.c)

# 目标include头文件目录
target_include_directories(1A PUBLIC include/ extern/openssl/include/ )
# 目标link库目录
target_link_directories(1A PUBLIC extern/openssl/)

# 目标链接 -lcrypto
target_link_libraries(1A PUBLIC -lcrypto)
