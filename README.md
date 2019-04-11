# quicly-chat
This is an example project to better understand the [quicly-lib](https://github.com/h2o/quicly)
The sample server will pass all incoming messages to all connected clients. The client itself will read input from `cin` and send it to the server. Incoming data will be printed to `cout`.

# how to build
There is a setup script that will download all dependancies. The client and server applications are built the usual way using cmake and make.
```
./setup.sh
mkdir build
cd build
cmake ..
make -j$(nproc)
```

# how to run
to run the quicly_server you first need to set an environment-variable to the folder containing `server.crt` and `server.key`.
```
export QUICLY_CERTS=/path/to/folder/
```
after that you can just run the server or client.
```
./quicly_server
./quicly_client
```