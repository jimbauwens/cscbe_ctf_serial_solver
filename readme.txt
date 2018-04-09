serial_killer was one of the challenges at the CSCBE 2018 finals. It is a typical CTF binary that checks a serial based on several constraints.

solve.py utilizes the dynamic symbolic execution engine of Triton along with the coupled Z3 SMT solver to automatically traverse the correct branches of the binary while solving all required constraints.
