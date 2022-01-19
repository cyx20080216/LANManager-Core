# LANManager-Core
It is a tool to manage and record the network activity in LAN.

It is based on [libtins](https://github.com/mfontanini/libtins), [gflags](https://github.com/gflags/gflags), [glog](https://github.com/google/glog) and [json](https://github.com/nlohmann/json).
# Build
1. Build [libtins](https://github.com/mfontanini/libtins) and [libpcap](https://github.com/the-tcpdump-group/libpcap) to get "libtins.a" and "libpcap.a".
2. Create directory "lib" in the directory of this project.
3. Put "libtins.a" and "libpcap.a" into the directory "lib".
4. Run `xmake`, them you can find the executable file in the directory "build"
# Run
```bash
sudo ./LANManager
```
To get help you should use this command:
```bash
./LANManager -h
```
# Configure
It is a example of the configure file
```json
{
    "interface":"xxx",
    "gateway":"xxx.xxx.xxx.xxx",
    "setting_table":{
        "xxx":{
            "type":"black/white",
            "ip":[
                "xxx.xxx.xxx.xxx",
                ...
            ]
        },
        ...
    },
    "target":[
        {
            "address":"xxx.xxx.xxx.xxx",
            "setting_table":"xxx"
        },
        ...
    ]
}
```