# 获取所有的源代码
file(GLOB SRC
  "${CMAKE_SOURCE_DIR}/apps/*.cpp"
  "${CMAKE_SOURCE_DIR}/include/*.hpp")

# 生成target 1B
add_executable(1B ${SRC})

# 目标include头文件目录
target_include_directories(1B PUBLIC
  "${CMAKE_SOURCE_DIR}/include/"
  "${CMAKE_SOURCE_DIR}/extern/openssl/include/")

# 目标link库目录
target_link_directories(1B PUBLIC
  "${CMAKE_SOURCE_DIR}/extern/openssl/")

# 目标链接 -lcrypto
target_link_libraries(1B PUBLIC -lcrypto)
