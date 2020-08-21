package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"

	//"os"
	"time"
)

type EInfo struct {
	Type string
	HostName string
	IPAddr string
	AuthoridCode string
}

type Package struct{
	Pubk string
	cipherText []byte
	time int64
}

func padding(src []byte, blocksize int) []byte {
	padnum := blocksize - len(src)%blocksize
	pad := bytes.Repeat([]byte{byte(padnum)}, padnum)
	return append(src, pad...)
}

func unPadding(src []byte) []byte {
	n := len(src)
	unPadNum := int(src[n-1])
	if unPadNum > n {
		return nil
	}
	return src[:n-unPadNum]
}

func EncryptAES(src []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	src = padding(src, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	blockMode.CryptBlocks(src, src)
	return src
}

func DecryptAES(src []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	blockMode.CryptBlocks(src, src)
	src = unPadding(src)
	return src
}

func generateEinfo() EInfo{
	info := EInfo{"edgeServer","Unbutu Linux","127.0.0.1","ANP1023456"}
	return info
}

/**
 */
func EncryptwithSK(einfo EInfo) []byte{
	msg := "AuthoridCode:"+einfo.AuthoridCode+" HostName:"+einfo.HostName+" IPAddr:"+einfo.IPAddr+" Type:"+einfo.Type
    fmt.Println("msg",msg)
	raw := []byte(msg)
	key := []byte("huyanyan87654321")
	encryptByte := EncryptAES(raw,key)
	return encryptByte
}

func InitPacket() Package{
	info := generateEinfo()
	encryptByte := EncryptwithSK(info)
	now := time.Now().UnixNano()
	Packet := Package{"hoyanrun87774541",encryptByte,now}
	return Packet
}

func sendRegistration() Package{
	pack := InitPacket()
	return pack
}

func receiveRegistration(pack Package) (bool,Package){
	key := []byte("huyanyan87654321")
	now := time.Now().UnixNano()
	if (now -pack.time)>10000{
		return false, Package{}
	}
	decryptByte := DecryptAES(pack.cipherText, key)
	if decryptByte != nil {
		fmt.Println(string(decryptByte))
	}
	return true, pack
}
/**

 */
func handleRegistration(pack Package){
	mskey := []byte("lizanyan87654321")
	sk := []byte("huyanyan87654321")
	decryptByte := DecryptAES(pack.cipherText,sk)
	infoMsg := string(decryptByte)
	raw := []byte(infoMsg)
	encryptByte := EncryptAES(raw,mskey)
	encryptMsg := string(encryptByte)
	pscontent := encryptMsg+"lizanyan87654321"+string(rand.Int63n(100))
	Ps :=  EncryptAES([]byte(pscontent),sk)
	PsName := hex.EncodeToString(Ps)
    fmt.Println("PsName:",PsName)
	content := "Pubk:"+pack.Pubk+";Info:"+encryptMsg+";PsName:"+PsName+";time:"+string(time.Now().UnixNano())
	fmt.Println(content)
	fimename := pack.Pubk+string(time.Now().UnixNano())+".txt"
	f,err := os.Create( fimename )
	defer f.Close()
	if err !=nil {
	fmt.Println( err.Error() )

	} else {
		_, err = f.Write([]byte(content))
		fmt.Println(err.Error())
	}
}


/**
 */
func main(){
	start := time.Now().UnixNano()
	pack := sendRegistration()
	flag, rpack := receiveRegistration(pack)
	if flag == true{
		handleRegistration(rpack)
	}
	end := time.Now().UnixNano()
	fmt.Printf("runtime: %v (ns)\n", end-start)
}
