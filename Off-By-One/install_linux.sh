apt-get update -y
# Installing dependencies for AFL++
apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools python3-pip ninja-build 
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
