#!/bin/bash

ROOT_DIR=$(pwd)

function setup () {
  cd $1
  mkdir build
  cd build
  cmake ..
  make -j${cores}
  cd ${ROOT_DIR}
}

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


git submodule update --init --recursive
echo "building picotls"
setup picotls

cd ${ROOT_DIR}
echo "building quicly"
setup quicly

