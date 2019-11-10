# 获取所有的源代码
file(GLOB SRC
  "${CMAKE_SOURCE_DIR}/apps/*.c"
  "${CMAKE_SOURCE_DIR}/include/*.h")

# 生成target 4A
add_executable(4A ${SRC})

# 目标include头文件目录
target_include_directories(4A PUBLIC
  "${CMAKE_SOURCE_DIR}/include/"
  "${CMAKE_SOURCE_DIR}/extern/openssl/include/")

# 目标link库目录
target_link_directories(4A PUBLIC
  "${CMAKE_SOURCE_DIR}/extern/openssl/")

# 目标链接 -lcrypto
target_link_libraries(4A PUBLIC -lssl -lcrypto)
