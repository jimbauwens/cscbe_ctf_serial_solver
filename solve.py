#!/usr/bin/env python2
## -*- coding: utf-8 -*-
##
## Solve the "Serial Killer" challenge from the CSCBE 2018 finals
## By Jim Bauwens
## Inspired by code from Jonathan Salwan

from triton import ARCH, TritonContext, MemoryAccess, CPUSIZE, Instruction, MODE, CALLBACK
import os
import sys

KEY_SIZE   = 19  # larger will also work
START_ADDR = 0x400729
END_ADDR   = 0x400AA1

# setup initial variables
variables = {}
for i in range(KEY_SIZE):
    variables[i] = ord('0')

# print the key
def print_key():
    out = ""
    for i in range(KEY_SIZE):
        out += chr(variables[i])
    print("[+] KEY: " + out)  


# Emulate the check_serial function.
def emulate(Triton, pc):
    print '[+] Starting emulation.'

    while pc:

        # Skip the strlen call
        if pc == 0x40074b:
            pc = 0x400760

        # If we are at the end of the serial checking function
        if pc == END_ADDR:
            # eax is 1 if solved, 0 if failed
            solved = Triton.getConcreteRegisterValue(Triton.registers.rax) != 0

            # if solved, print the key
            if solved:
                print("[+] Found solution")
                print_key()
                break
    
            # if not, we took a wrong branch, fix it
            else:
                print("[+] Not yet a complete solution...")

                # the branch contraints for the last jump
                top_constraint = Triton.getPathConstraints().pop().getBranchConstraints()

                # the other path constraints of previous jumps
                oth_constraints = Triton.getPathConstraintsAst().getChildren()[0]

                # if we took branch 0 we need the constraints for branch 1 (and opposite)
                gb = top_constraint[0]['isTaken'] and 1 or 0
                good_top = top_constraint[gb]['constraint']
            
                # combine the constraints again
                cstr = Triton.getAstContext().land([oth_constraints, good_top])
           
                # try to find a model
                print '[+] Asking for a model, please wait...'
                model  = Triton.getModel(cstr)
                mitems = model.items()

                # if something is still wrong with our code we might get no result
                if len(mitems) == 0:
                    print("[+] UNSAT, ending emulation")
                    break

                # print model
                for k, v in mitems:
                    value = v.getValue()
                    # put values in variable list
                    variables[k] = value
                    print '[+] Symbolic variable %02d = %02x (%c)' %(k, value, chr(value))

                # reset emulation
                print("[+] Retrying with new model")
                print("")
                Triton = initialize()
                pc = START_ADDR
                continue


        # Fetch opcode
        opcode = Triton.getConcreteMemoryAreaValue(pc, 16)

        # Create the Triton instruction
        instruction = Instruction()
        instruction.setOpcode(opcode)
        instruction.setAddress(pc)

        # Process
        Triton.processing(instruction)
        #print instruction

        # Next
        pc = Triton.getConcreteRegisterValue(Triton.registers.rip)

    print '[+] Emulation done.'
    return


# Load segments into triton.
def loadBinary(Triton, path):
    import lief
    lief.Logger.disable()
    binary = lief.parse(path)
    phdrs  = binary.segments
    for phdr in phdrs:
        size   = phdr.physical_size
        vaddr  = phdr.virtual_address
        #print '[+] Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size)
        Triton.setConcreteMemoryAreaValue(vaddr, phdr.content)
    return

# Setup emulation
def initialize():
    Triton = TritonContext()
    Triton.setArchitecture(ARCH.X86_64)

    # Define optimizations
    Triton.enableMode(MODE.ALIGNED_MEMORY, True)

    # Load the binary
    loadBinary(Triton, os.path.join(os.path.dirname(__file__), 'serial_killer'))

    # Define a fake stack
    Triton.setConcreteRegisterValue(Triton.registers.rbp, 0x7fffffff)
    Triton.setConcreteRegisterValue(Triton.registers.rsp, 0x6fffffff)

    # Define an user input
    Triton.setConcreteRegisterValue(Triton.registers.rdi, 0x10000000)

    # Symbolize user inputs 
    for index in range(KEY_SIZE):
        Triton.setConcreteMemoryValue(MemoryAccess(0x10000000+index,  CPUSIZE.BYTE), variables[index])
        Triton.convertMemoryToSymbolicVariable(MemoryAccess(0x10000000+index, CPUSIZE.BYTE))

    return Triton

if __name__ == '__main__':
    # Initialize symbolic emulation
    Triton = initialize()

    # Emulate from the verification function
    emulate(Triton, START_ADDR)

    sys.exit(0)

