// +build linux

package main

/*
#include <linux/kvm.h>
*/
import "C"

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	//from /uapi/linux/kvm.h
	ExitReasonUknown int = iota
	ExitReasonException
	ExitReasonIO
	ExitReasonHyperCall
	ExitReasonDebug
	ExitReasonHLT
	ExitReasonMMIO
	ExitReasonIRQWindowOpen
	ExitReasonShutdown
	ExitReasonFailEntry
	ExitReasonINTR
	ExitReasonSetTPR
	ExitReasonTPRAcess
	ExitReasonS390SIEIC
	ExitReasonS390RESET
	ExitReasonDCR
	ExitReasonNMI
	ExitReasonInternalEerror
	ExitReasonOSI
	ExitReasonPAPRHCALL
	ExitReasonS390UCONTROL
	ExitReasonWATCHDOG
	ExitReasonS390TSCH
	ExitReasonEPR
	ExitReasonSystemEvent
	ExitReasonS390STSI
	ExitReasonIOAPICEOI
	ExitReasonHYPERV
	ExitReasonARMNISV
)

//KVMExitIO Port I/O exit info
type KVMExitIO struct {
	direction  C.__u8
	size       C.__u8
	port       C.__u16
	count      C.__u32
	dataOffset C.__u64 //bytes from kvm_run start
}

func main() {
	run(os.Stdout)
}

func run(com1Out io.Writer) {
	code := []uint8{
		0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */ //set output port to 0x3f8 (COM1 port)
		0x00, 0xd8, /* add %bl, %al */ //a + b
		0x04, '0', /* add $'0', %al */ //shift to ascii value of numeric
		0xee,       /* out %al, (%dx) */ //output character
		0xb0, '\n', /* mov $'\n', %al */ //set al to new line character
		0xee, /* out %al, (%dx) */ //output character
		0xf4, /* hlt */            //halt cpu
	}

	kvm, err := syscall.Open("/dev/kvm", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(kvm)

	if err := validateVersion(kvm); err != nil {
		panic(err)
	}

	vm, err := createVM(kvm)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(vm)

	memsize := 0x1000

	mem, err := syscall.Mmap(-1, 0, memsize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_ANONYMOUS)
	if err != nil {
		panic(err)
	}

	//Copy code into RAM slot
	if n := copy(mem, code); n == 0 {
		panic("failed to copy code to RAM")
	}

	var region C.struct_kvm_userspace_memory_region
	region.slot = 0
	region.guest_phys_addr = 0x1000
	region.memory_size = C.__u64(memsize)
	region.userspace_addr = C.__u64(uintptr(unsafe.Pointer(&mem[0])))

	_, _, e := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(vm),
		uintptr(C.KVM_SET_USER_MEMORY_REGION),
		uintptr(unsafe.Pointer(&region)))
	if e != 0 {
		panic("failed to set mem region")
	}

	vcpu, err := createVCPU(vm)
	if err != nil {
		panic(err)
	}

	mmapSize, err := getVCPUMMapSize(kvm)
	if err != nil {
		panic(err)
	}

	var run *C.struct_kvm_run

	if mmapSize < C.sizeof_struct_kvm_run {
		panic("MMap unexpectedly small")
	}

	runB, _ := syscall.Mmap(vcpu, 0, mmapSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if runB == nil {
		panic("failed to get run")
	}
	//Type cast the packed byte array to a usable C struct
	run = (*C.struct_kvm_run)(unsafe.Pointer(&runB[0]))

	var sregs C.struct_kvm_sregs
	if err := getVCPUSRegs(vcpu, &sregs); err != nil {
		panic(err)
	}
	sregs.cs.base = 0
	sregs.cs.selector = 0
	if err := setVCPUSRegs(vcpu, &sregs); err != nil {
		panic(err)
	}

	var regs C.struct_kvm_regs
	regs.rip = 0x1000
	regs.rax = 2
	regs.rbx = 2
	regs.rflags = 0x2

	if err := setVCPURegs(vcpu, &regs); err != nil {
		panic(err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for {
		ret, err := runVCPU(vcpu)
		if err != nil || ret == -1 {
			panic(err)
		}
		switch int(run.exit_reason) {
		case ExitReasonHLT:
			log.Println("exit: HLT")
			return
		case ExitReasonIO:
			//Type cast the union object in kvm_run struct, why cgo no support unions!
			exit := (*KVMExitIO)(unsafe.Pointer(&run.anon0[0]))
			data := (*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&runB[0])) + uintptr(exit.dataOffset)))

			handlePio(exit, data, com1Out)
			break
		}
	}
}

func handlePio(pio *KVMExitIO, data *uint64, com1Out io.Writer) {
	if pio.port == 0x3f8 && pio.direction == C.KVM_EXIT_IO_OUT {
		com1Out.Write([]byte(fmt.Sprintf("%c", rune(*data))))

	}
}

func runVCPU(vcpuFd int) (int, error) {
	ret, _, e := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(vcpuFd),
		uintptr(C.KVM_RUN),
		0)
	if e != 0 {
		return -1, fmt.Errorf("failed to run cpu")
	}
	return int(ret), nil
}

func getVCPUSRegs(vcpuFd int, sregs *C.struct_kvm_sregs) error {
	_, _, e := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(vcpuFd),
		uintptr(C.KVM_GET_SREGS),
		uintptr(unsafe.Pointer(sregs)))
	if e != 0 {
		return fmt.Errorf("failed to get sregs: %d", e)
	}
	return nil
}

func setVCPUSRegs(vcpuFd int, sregs *C.struct_kvm_sregs) error {
	_, _, e := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(vcpuFd),
		uintptr(C.KVM_SET_SREGS),
		uintptr(unsafe.Pointer(sregs)))
	if e != 0 {
		return fmt.Errorf("failed to set sregs: %d", e)
	}
	return nil
}

func setVCPURegs(vcpuFd int, regs *C.struct_kvm_regs) error {
	_, _, e := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(vcpuFd),
		uintptr(C.KVM_SET_REGS),
		uintptr(unsafe.Pointer(regs)))
	if e != 0 {
		return fmt.Errorf("failed to set vcpu regs")
	}
	return nil
}

func getVCPUMMapSize(kvmFd int) (int, error) {
	size, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(kvmFd),
		uintptr(C.KVM_GET_VCPU_MMAP_SIZE),
		0)
	if err != 0 {
		return 0, fmt.Errorf("failed to get MMap size")
	}

	return int(size), nil
}

func createVM(kvmFd int) (int, error) {
	vmFd, _, e := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(kvmFd),
		uintptr(C.KVM_CREATE_VM),
		0)

	if e != 0 {
		return 0, fmt.Errorf("failed to create VM")
	}

	return int(vmFd), nil
}

func createVCPU(vmFd int) (int, error) {
	vcpuFd, _, e := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(vmFd),
		uintptr(C.KVM_CREATE_VCPU),
		0)
	if e != 0 {
		return 0, fmt.Errorf("failed to create VCPU")
	}
	return int(vcpuFd), nil
}

func validateVersion(kvmFd int) error {
	version, _, e := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(kvmFd),
		uintptr(C.KVM_GET_API_VERSION),
		0)
	if e != 0 {
		return fmt.Errorf("Failed to get KVM version")
	}

	if version != 12 {
		return fmt.Errorf("Incompatible KVM version")
	}

	return nil
}
