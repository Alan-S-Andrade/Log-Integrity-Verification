# Log-Integrity-Verification

Simple utility for the verification of Linux Audit log integrity proofs.

Compile with:
  
   make

Usage:
  
  ./proof [INITIAL FIRST SIGNING KEY] [path of audit log file to verify]

Audtit log files to prove must start at the beggining of the proof cycle and each log record must follow sequentially in the order in which they were initially logged.
