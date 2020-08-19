package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/ecies"
	"os"
	"time"
)

func sha256Test(){
	Myhash := sha256.New()
    Msg := []byte("Hello from test games,Hello from test games,Hello from test games")
    res := Myhash.Sum(Msg)
	format_str := hex.EncodeToString(res)
    fmt.Printf("this is: %s\n",format_str)
}
/////////////////////////////////////////////////////////////////////////////////////AES
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

func AESTest() []byte {
	raw := []byte("guoshuaijieffggggggg")
	key := []byte("huyanyan87654321")
	encryptByte := EncryptAES(raw, key)
	if encryptByte != nil {
		decryptByte := DecryptAES(encryptByte, key)
		if decryptByte != nil {
			fmt.Println(string(decryptByte))
		}
	}
	return nil
}
////////////////////////////////////////////////////////////////////////////////AES
////////////////////////////////////////////////////////////////////////////////RSA
func GenerateRSAKey(bits int) {
	//GenerateKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥
	//Reader是一个全局、共享的密码用强随机数生成器
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}

	X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	privateFile, err := os.Create("private.pem")
	if err != nil {
		panic(err)
	}
	defer privateFile.Close()
	//构建一个pem.Block结构体对象
	privateBlock := pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}
	//将数据保存到文件
	pem.Encode(privateFile, &privateBlock)

	//保存公钥
	//获取公钥的数据
	publicKey := privateKey.PublicKey
	//X509对公钥编码
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}

	publicFile, err := os.Create("public.pem")
	if err != nil {
		panic(err)
	}
	defer publicFile.Close()
	//创建一个pem.Block结构体对象
	publicBlock := pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}
	//保存到文件
	pem.Encode(publicFile, &publicBlock)
}


func RSAEncrypt(plainText []byte, path string)  []byte{
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	//读取文件的内容
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)
	//x509解码

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//类型断言
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	//对明文进行加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		panic(err)
	}
	//返回密文
	return cipherText
}

func RsaDecrypt(cipherText []byte,path string) []byte {
	file,err:=os.Open(path)
	if err!=nil{
		panic(err)
	}
	defer file.Close()
	//获取文件内容
	info, _ := file.Stat()
	buf:=make([]byte,info.Size())
	file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)
	//X509解码
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err!=nil{
		panic(err)
	}
	//对密文进行解密
	plainText,_:=rsa.DecryptPKCS1v15(rand.Reader,privateKey,cipherText)
	//返回明文
	return plainText
}

func RsaTest(){
	GenerateRSAKey(2048)
	data := []byte("hello world")
	encrypt :=RSAEncrypt(data, "public.pem")
	fmt.Println(string(encrypt))
	// 解密
	decrypt := RsaDecrypt(encrypt, "private.pem")
	fmt.Println(string(decrypt))
}
//////////////////////////////////////////////////////////////////////////////////////////////RSA
/////////////////////////////////////////////////////////////////////////////////////////////ECC
// generate ECC  key
func GenerateECCKey(){
	//生成密钥对
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	//保存私钥
	//生成文件
	privatefile, err := os.Create("eccprivate.pem")
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
	publicfile, err := os.Create("eccpublic.pem")
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

//取得ECC私钥
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

func ECCTest(){
	GenerateECCKey()
	msg := []byte("hello from ECC")
	cipherBytes := ECCEncrypt("eccpublic.pem",msg) //cipherBytes :=
	decryptString := ECCDecrypt ("eccprivate.pem",cipherBytes)
	fmt.Println("解密数据: \n" + string(decryptString))
}

//////////////////////////////////////////////////////////////////////////////////////ECC


func main(){
	start := time.Now().UnixNano()
	sha256Test()
	end := time.Now().UnixNano()
	fmt.Printf("runtime: %v (ns)\n", end-start)
	start = time.Now().UnixNano()
	AESTest()
	end = time.Now().UnixNano()
	fmt.Printf("runtime: %v (ns)\n", end-start)
	start = time.Now().UnixNano()
	RsaTest()
	end = time.Now().UnixNano()
	fmt.Printf("runtime: %v (ns)\n", end-start)
	start = time.Now().UnixNano()
	ECCTest()
	end = time.Now().UnixNano()
	fmt.Printf("runtime: %v (ns)\n", end-start)
}
