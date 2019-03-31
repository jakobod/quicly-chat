#!/bin/bash

ROOT_DIR=$(pwd)

# figure out core number
cores=4
if [[ "$(uname)" == "Darwin" ]]; then
  cores=$(sysctl -n hw.ncpu)
elif [[ "$(uname)" == "FreeBSD" ]]; then
  cores=$(sysctl -n hw.ncpu)
elif [[ "$(expr substr $(uname -s) 1 5)" == "Linux" ]]; then
  cores=$(nproc --all)
fi
echo "Using $cores cores for compilation."


echo 'building picotls'
if cd ${ROOT_DIR}/picotls
then
  git pull
  cd build
else
  cd ${ROOT_DIR}
  git clone https://github.com/h2o/picotls.git
  cd picotls
  git submodule update --init --recursive
  mkdir build
  cd build
fi
cmake ..
make -j${cores}

cd ${ROOT_DIR}
echo "building quicly"
if cd quicly; then
  git pull
  git submodule update --recursive
  cd build
else
 git clone https://github.com/h2o/quicly.git
 cd quicly
 git submodule update --init --recursive
 mkdir build
 cd build
fi
cmake ..
make -j$cores
