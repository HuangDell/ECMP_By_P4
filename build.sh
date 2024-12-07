#!/bin/bash
# 定义变量
P4_NAME="let_it_flow"
SRC_NAME="flowlet"

P4FILE_PATH="$(pwd)/src/${SRC_NAME}.p4"
BUILD_DIR="build"

# 检查 build 文件夹是否存在
if [ -d "$BUILD_DIR" ]; then
  echo "Directory $BUILD_DIR exists. Deleting..."
  sudo rm -rf "$BUILD_DIR"
else
  echo "Directory $BUILD_DIR does not exist."
fi

# 创建并进入 build 文件夹
mkdir "$BUILD_DIR"
cd "$BUILD_DIR"

# 执行编译操作
cmake "$SDE/p4studio/" -DCMAKE_INSTALL_PREFIX="$SDE/install" -DCMAKE_MODULE_PATH="$SDE/cmake" -DP4_NAME="$P4_NAME" -DP4_PATH="$P4FILE_PATH"
make $P4_NAME
make install