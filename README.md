# KVM Example

Taken from the original KVM example in the linux documentation, but rewritten to Go (mostly).

- Sets up a new KVM VM
- Creates 4KB of RAM
- Copies the assembly code into RAM
- Creates a vCPU
- Sets up vCPU sregs/regs with input and instruction pointer
- Execute until PIO or HLT
