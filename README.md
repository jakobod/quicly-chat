# quicly-chat
This is an example project to better understand the [quicly-lib](https://github.com/h2o/quicly)
The sample server will pass all incoming messages to all connected clients. The client itself will read input from `cin` and send it to the server. Incoming data will be printed to stdout.

# how to build
There is a setup script that will download all dependancies. The client and server applications are built the usual way using cmake and make.
```
./setup.sh
mkdir build
cd build
cmake ..
make -j$(nproc)
```
