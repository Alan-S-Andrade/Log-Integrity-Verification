## Log-Integrity-Verification

Simple utility for the verification of Linux Audit log integrity proofs.

Compile with:
  
   make

Usage:
  
  ./proof [INITIAL FIRST SIGNING KEY] [path of audit log file to verify]

Audtit log files to prove must start at the beggining of the proof cycle and each log record must follow sequentially in the order in which they were initially logged.

# Kernel build instructions:

$ sudo apt install -y build-essential ocaml automake autoconf libtool wget python libssl-dev bc swig flex bison libelf-dev libldap2-dev auditd python3-dev python-dev libwrap0-dev libcap-ng-deb

$ sudo make defconfig && sudo make -j8 && sudo make modules_install install && sudo make headers && sudo find usr/include -name '.*' -delete && sudo rm usr/include/Makefile && sudo cp -rv usr/include $LFS/usr

