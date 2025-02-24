# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure("2") do |config|
  config.vm.define "dct-dev-t" 
  config.vm.box = "bento/ubuntu-20.04"
  config.vm.hostname = "dct"
  config.vm.provider "virtualbox" do |vb|
    vb.name = "dct-dev-t"
    vb.cpus = "8"
    vb.memory = "16384"
  end
  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    sudo apt-get update
    sudo apt-get -y install gcc-10 g++-10 build-essential \
                            pkg-config python3-minimal libboost-all-dev \
                            libssl-dev libsqlite3-dev libpcap-dev \
                            libsodium-dev libz-dev \
                            liblog4cxx-dev
    sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 100
    sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-10 100
    sudo update-alternatives --install /usr/bin/c++ c++ /usr/bin/g++-10 100
    git clone https://github.com/pollere/NDNpatches
    git clone https://github.com/named-data/ndn-cxx
    cd ndn-cxx
    git apply ../NDNpatches/patch.key-impl
    ./waf configure
    ./waf
    sudo ./waf install
    sudo ldconfig
    cd ..
    git clone https://github.com/named-data/NFD
    cd NFD
    git apply ../NDNpatches/cxx-register-bug.patch
    git submodule update --init
    ./waf configure
    ./waf
    sudo ./waf install
    sudo cp /usr/local/etc/ndn/nfd.conf.sample /usr/local/etc/ndn/nfd.conf
    cd ..

    git clone https://github.com/ucla-irl/ndn-ind
    cd ndn-ind
    ./configure
    make -j
    sudo make install
    sudo ldconfig
    cd ..
    
    git clone https://github.com/named-data/ndn-svs
    cd ndn-svs
    git checkout develop
    ./waf configure
    ./waf
    sudo ./waf install
    cd ..
    sudo ldconfig

    rm -rf DCT
    git clone https://github.com/pulsejet/DCT DCT 
    cd DCT/
    git checkout main
    cd tools/
    make -j
    cd ../examples/mbps
    make -j
    wget https://github.com/pollere/DCT/releases/download/v3.0/linux-schemaCompile-bin-1.2.0.tgz
    tar -xzvf linux-schemaCompile-bin-1.2.0.tgz
    rm linux-schemaCompile-bin-1.2.0.tgz
    bash sec_bootstrap.sh
    cd ../../..
    sudo ldconfig
    ndnsec key-gen /ndn/alice
    nfd-start || echo
    sleep 1
    nfdc strategy set /localnet /localhost/nfd/strategy/multicast/v=4
  SHELL
end

