package main

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
	"crypto/sha256"

)

type block struct {
	PS string
	Pubk string
	nonce int
}

func GetDurTime() float64 {
	kernel := syscall.NewLazyDLL("Kernel32.dll")
	GetTickCount := kernel.NewProc("GetTickCount")
	r, _, _ := GetTickCount.Call()
	if r == 0 {
		return 0.0
	}
	return float64(r)
}

func ObtainFreeMem() float64{
	kernel32, err := syscall.LoadLibrary("Kernel32.dll")
	if err != nil {
		log.Panic(err)
	}
	defer syscall.FreeLibrary(kernel32)
	GetDiskFreeSpaceEx, err := syscall.GetProcAddress(syscall.Handle(kernel32), "GetDiskFreeSpaceExW")

	if err != nil {
		log.Panic(err)
	}

	lpFreeBytesAvailable := int64(0)
	lpTotalNumberOfBytes := int64(0)
	lpTotalNumberOfFreeBytes := int64(0)
	r, a, b := syscall.Syscall6(uintptr(GetDiskFreeSpaceEx), 4,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("C:"))),
		uintptr(unsafe.Pointer(&lpFreeBytesAvailable)),
		uintptr(unsafe.Pointer(&lpTotalNumberOfBytes)),
		uintptr(unsafe.Pointer(&lpTotalNumberOfFreeBytes)), 0, 0)
	fmt.Println(r,a,b)
	log.Printf("Available  %dmb", lpFreeBytesAvailable/1024/1024.0)
	log.Printf("Total      %dmb", lpTotalNumberOfBytes/1024/1024.0)
	log.Printf("Free       %dmb", lpTotalNumberOfFreeBytes/1024/1024.0)
	return float64(lpTotalNumberOfFreeBytes / 1024 / 1024.0)
}


func objToStr(obj block) string{
	str_nonce := strconv.Itoa(obj.nonce)
	str_pubk := obj.Pubk
	str_ps := obj.PS
	//fmt.Println(str_dur+str_utime)
	return str_nonce+str_pubk+str_ps
}

func converToInteger(hashcode string) int{
	length := len(hashcode)
	sum := 0
	for i := 0;i<length;i++{
		tmp := int (hashcode[i]-'0')
		sum = int(tmp + sum)
	}
	return sum
}

//取得ECC公钥
func GetECCPublicKey(path string) string {
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解密
	block, _ := pem.Decode(buf)
	//x509解密
	hex.EncodeToString(block.Bytes)

	return hex.EncodeToString(block.Bytes)
}

/**

 */
func PoWD(){
	var INT_MAX = 220000000000000
	var D float64
	Mem:=ObtainFreeMem()
	Dur:=GetDurTime()
	fmt.Println("Current Mem,Dur",Mem,Dur)
	if Mem == 0.0 || Dur == 0.0{
		D = float64(INT_MAX)
	}else {
		total := Mem*Mem + Dur*Dur
		theta1 := float64((Mem * Mem) / total)
		theta2 := (float64)((Dur * Dur) / total)
		fmt.Println(theta1, theta2)
		F := theta1*Mem + theta2*Dur
		fmt.Println("F:=", F)
		D = float64(INT_MAX) / F
		fmt.Println("D=", D)
	}

	Pubk := GetECCPublicKey("eccpublic.pem") //obtain the public key of entity
    fmt.Println("Pubk",Pubk)
	for nonce :=0; nonce< INT_MAX; nonce++ {
		b := block{"09a9f8e9e056749d0db84152be5f2af78b4aeb7a9359c69a684e3f1d64b65b33c9db7b9e95c861ea397b952f91a42d23",
			Pubk,
			int(nonce)}
		Myhash := sha256.New()
		str_block := objToStr(b)
		res := Myhash.Sum([]byte(str_block))
		hash_str := hex.EncodeToString(res)
		fmt.Println("hash_str:=",hash_str)
		sum := converToInteger(hash_str)
		fmt.Println("sum:=",sum)
		target := float64(sum*100.0)
		if (target > D){
			break;
		}
	}
}

func main() {
	start := time.Now().UnixNano()
	PoWD()
	end := time.Now().UnixNano()
	fmt.Printf("runtime: %v (ns)\n", end-start)
}
