# AFL++
apt-get update
apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools python3-pip
apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
apt-get install -y ninja-build # for QEMU mode
pip install unicorn

## Install a specific version of LLVM:
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 17 # <version number> 
export LLVM_CONFIG=llvm-config-17 # Adding to variable env
echo 'Defaults env_keep += "LLVM_CONFIG=llvm-config-17"' | sudo EDITOR='tee -a' visudo # Adding to sudo 
## Download AFL
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make
sudo make install
cd .. ## AFL installation is done return to starting directory


# LibAFL
 curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh # Install rust
 cargo install cargo-make # Install cargo make
 git clone https://github.com/AFLplusplus/LibAFL # Clone LibAFL
 cd LibAFL
 cargo build --release
 cd .. # LibAFL installation is done, return to starting directory
 
# LibFuzzer 
## Is already installed with clang

# honggfuzz
apt-get -y  install binutils-dev libunwind-dev libblocksruntime-dev 
git clone https://github.com/google/honggfuzz
cd honggfuzz
make 
cd .. # hongfuzz installation is done, return to starting directory

# SemGrep
python3 -m pip install semgrep # install through pip
## Semgrep installation is done
# cppCheck
apt-get -y  install cppcheck
## cppcheck installation is done

# CodeQL
wget https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.17.6/codeql-bundle-linux64.tar.gz # Download CodeQL release
tar -xf codeql-bundle-linux64.tar.gz # extract the archive
export PATH="$PATH:$(pwd)/codeql" # Adding codeql to path


# Clang static analyzer
git clone https://github.com/llvm/llvm-project.git # Clonig repo
cd llvm-project 
mkdir build # Creating build dir
cd build
cmake -DLLVM_ENABLE_PROJECTS=clang -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" ../llvm  # Prepare makefile
make 
make install # Installation
cd ../../ # Installation of CSA is done, return to starting directory
