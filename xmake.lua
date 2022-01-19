add_requires("gflags",{system=false})
add_requires("glog",{system=false})
add_requires("nlohmann_json",{system=false})
-- I need libtins that is depands on OpenSSL 
add_requires("openssl",{system=false})
target("LANMananger")
    set_kind("binary")
    -- Set CXX
    set_languages("c++17")
    -- Set libraries directory
    add_linkdirs("lib")
    -- Add co
    add_syslinks("backtrace")
    add_packages("co")
    -- Add gflags
    add_packages("gflags")
    -- Add glog
    add_packages("glog")
    -- Add nlohmann_json
    add_packages("nlohmann_json")
    -- Add libpcap
    add_links("pcap")
    -- Add linbtins
    add_packages("openssl")
    add_links("tins")
    -- Add code
    add_includedirs("include")
    add_files("src/*.cpp")