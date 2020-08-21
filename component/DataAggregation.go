package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/ecies"
	"math/big"
	"os"
	. "strconv"
	"crypto/sha256"
	"time"
)

type sData struct {
	humidity float64
	temperature float64
	weight float64
	latitude float64
	longitude float64
}

/**
 */
type packetData struct {
	cryptContent []byte
	rSig []byte
	sSig []byte
	timestamp int64
}
func GenerateECCKey(){
	//生成密钥对
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	//保存私钥
	//生成文件
	privatefile, err := os.Create("eccprivate-1.pem")
	if err != nil {
		panic(err)
	}
	//x509编码
	eccPrivateKey, err := x509.MarshalECPrivateKey(privateKey)

	if err != nil {
		panic(err)
	}
	//pem编码
	privateBlock := pem.Block{
		Type:  "ecc private key",
		Bytes: eccPrivateKey,
	}
	pem.Encode(privatefile, &privateBlock)
	//保存公钥
	publicKey := privateKey.PublicKey
	//创建文件
	publicfile, err := os.Create("eccpublic-1.pem")
	//x509编码
	eccPublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	//pem编码
	block := pem.Block{Type: "ecc public key", Bytes: eccPublicKey}
	pem.Encode(publicfile, &block)
	defer publicfile.Close()

}

func GetECCPrivateKey(path string) *ecdsa.PrivateKey {
	//读取私钥
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)
	//x509解码
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return privateKey
}

//取得ECC公钥
func GetECCPublicKey(path string) *ecdsa.PublicKey {
	//读取公钥
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
	publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	publicKey := publicInterface.(*ecdsa.PublicKey)
	return publicKey
}

func ECCEncrypt(path string ,message []byte) []byte{
	publicKey := GetECCPublicKey(path)
	eciesPublicKey := ecies.ImportECDSAPublic(publicKey)
	cipherBytes, _ := ecies.Encrypt(rand.Reader, eciesPublicKey, message, nil, nil)
	//cipherString := hex.EncodeToString(cipherBytes)
	//fmt.Println("加密数据: \n" + cipherString)
	return  cipherBytes
}


func ECCDecrypt(path string, message []byte) []byte{
	privatekey := GetECCPrivateKey(path)
	eciesPrivateKey := ecies.ImportECDSA(privatekey)
	decrypeMessageBytes, _ := eciesPrivateKey.Decrypt(rand.Reader, message, nil, nil)
	//decryptString := hex.EncodeToString(decrypeMessageBytes)
	//fmt.Println("解密数据: \n" + decryptString)
	return decrypeMessageBytes
}

/**
 */
func generateSdata() sData{
	sdata := sData{36.4,31.8,2.5,116.2790,39.733}
	return sdata
}

/**
 */
func EncryptSdata(sdata sData) []byte{
	humidity := FormatFloat(sdata.humidity,'g', 6, 64)
	temperature := FormatFloat(sdata.temperature,'g', 6, 64)
	weight := FormatFloat(sdata.weight,'g', 6, 64)
	latitude := FormatFloat(sdata.latitude,'g', 6, 64)
	longitude := FormatFloat(sdata.longitude,'g', 6, 64)
	msg := "humidity:"+humidity+";temperature:"+temperature+";weight:"+weight+";latitude:"+latitude+";longitude:"+longitude
	fmt.Println("msg:"+msg)
	cipherBytes := ECCEncrypt("eccpublic.pem", []byte(msg)) //public key of ES
	return cipherBytes
}

/**

 */
func ECCSign(path string, cipherBytes []byte)([]byte, []byte){
	Myhash := sha256.New()
	res := Myhash.Sum(cipherBytes)
	privatekey := GetECCPrivateKey(path)
	r,s,err := ecdsa.Sign(rand.Reader,privatekey,res)
	if err !=nil{
		panic(err)
	}
	rText,err1 := r.MarshalText()
	if err1 !=nil{
		panic(err1)
	}
	sText, err2 := s.MarshalText()
	if err2 !=nil{
		panic(err2)
	}
	return  rText, sText
}

func ECCVerify(cipherBytes []byte,rText []byte, sText []byte,path string) bool{
	Myhash := sha256.New()
	res := Myhash.Sum(cipherBytes)
	publicKey := GetECCPublicKey(path)
	var r, s big.Int
	r.UnmarshalText(rText)
	s.UnmarshalText(sText)
	ret := ecdsa.Verify(publicKey,res,&r,&s) //ES verifies the signature from LC
	return ret
}


func LCPrepareData () packetData{
	sData := generateSdata() //LC generate data
	cipherBytes := EncryptSdata(sData) //LC encrtypt the data with public key of ES
	rText,sText := ECCSign("eccprivate-1.pem",cipherBytes)
	now := time.Now().UnixNano()
	pData := packetData{cipherBytes,rText,sText,now}
	return pData
}

func receiveData (pData packetData)(bool,packetData){
	now := time.Now().UnixNano()
	if (now -pData.timestamp)>10000{
		return false, packetData{}
	}
	ret := ECCVerify(pData.cryptContent,pData.rSig,pData.sSig,"eccpublic-1.pem")
	if ret == true{
		dept := ECCDecrypt("eccprivate.pem",pData.cryptContent) //decrypt by private key of ES
		str := string(dept)
		fmt.Println("strdata:=",str)
	}
	return ret, packetData{}
}


func main(){
	start := time.Now().UnixNano()
	//GenerateECCKey() //LCs keys
	pData := LCPrepareData() //Prepare data for ESs
	receiveData(pData) //ESs receive data and process this received data
	end := time.Now().UnixNano()
	fmt.Printf("runtime: %v (ns)\n", end-start)
}