apt-get update -y
###################################
# Installing AFL++
# Dependencies
apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools python3-pip ninja-build gcc libncurses-dev libelf-dev libssl-dev
apt install qemu-system-x86
pip install unicorn

# Installing clang for AFL++
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 17
export LLVM_CONFIG=llvm-config-17

# Installing AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make
sudo make install
cd ..
###################################
# Install fuzzili
wget https://github.com/googleprojectzero/fuzzilli/archive/refs/tags/v0.9.3.tar.gz
tar -xf v0.9.3.tar.gz
cd fuzzilli-0.9.3.tar.gz
swift build -c release -Xlinker='-lrt'
cd ..
###################################
# Install syzkaller
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
