package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/ecies"
	_ "github.com/go-sql-driver/mysql"
	"os"
	"strconv"
	"time"
)

type LogisticsRd struct {
	CTcontent string
	status int64
	stkey string
}

type sData struct {
	humidity float64
	temperature float64
	weight float64
	latitude float64
	longitude float64
}

func generateSdata() sData{
	sdata := sData{109.4,99.9,10.5,199.5790,99.733}
	return sdata
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

func EncryptSdata(sdata sData) []byte{
	humidity := strconv.FormatFloat(sdata.humidity,'g', 6, 64)
	temperature := strconv.FormatFloat(sdata.temperature,'g', 6, 64)
	weight := strconv.FormatFloat(sdata.weight,'g', 6, 64)
	latitude := strconv.FormatFloat(sdata.latitude,'g', 6, 64)
	longitude := strconv.FormatFloat(sdata.longitude,'g', 6, 64)
	msg := "humidity:"+humidity+";temperature:"+temperature+";weight:"+weight+";latitude:"+latitude+";longitude:"+longitude
	fmt.Println("msg:"+msg)
	cipherBytes := ECCEncrypt("eccpublic.pem", []byte(msg)) //public key of ES
	return cipherBytes
}

func generateIndex() string{
	// Assume ES PSname is
	PSname := "09a9f8e9e056749d0db84152be5f2af78b4aeb7a9359c69a684e3f1d64b65b33c9db7b9e95c861ea397b952f91a42d23"
    //Public key is: hoyanrun87774541
	Pubk := "hoyanrun87774541"
	Content := PSname+Pubk
	Myhash := sha256.New()
	res := Myhash.Sum([]byte(Content))
	skey := hex.EncodeToString(res)
	return skey
}

/**

 */
func storeDataToCS (ldata LogisticsRd){
	var db, err = sql.Open("mysql", "root:root@tcp(localhost:3306)/test?charset=utf8")
	if err !=nil{
		panic(err)
	}
	stmt, err1 := db.Prepare("insert into endata (CTcontent,stkey,status) VALUES (?,?,?)")
	if err1 != nil {
		fmt.Printf("insert prepare err:%s\n", err.Error())
		return
	}
	defer stmt.Close()

	res, err2 := stmt.Exec(ldata.CTcontent,ldata.stkey,ldata.status)
	if err2 != nil {
		fmt.Printf("insert err:%s\n", err.Error())
		return
	}
	lastId, _ := res.LastInsertId()
	affect, _ := res.RowsAffected()
	fmt.Printf("lastId:%d affectRow:%d\n", lastId, affect)
}

/**

 */
func searchfromCSbyKey(key string ) []string{
	db, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/test?charset=utf8")
	var sql_str string
	sql_str = "SELECT CTcontent from endata where status=1 and stkey="+"'"+key+"'"
	//fmt.Println(sql_str)
	stmt, err := db.Prepare(sql_str)
	if err != nil {
		fmt.Printf("query prepare err:%s\n", err.Error())
	}
	defer stmt.Close()
	rows, err := stmt.Query()
	if err != nil {
		fmt.Printf("query err:%s\n", err.Error())
	}
	var Dataset []string
	for rows.Next() {
		var CTcontent string
		err =rows.Scan(&CTcontent)
		if err !=nil{
			panic(err)
		}
		Dataset = append(Dataset,CTcontent)
	}
	return Dataset
}


func dataAudit(thash string, stkey string) bool{
	RdSet := searchfromCSbyKey(stkey)
	//fmt.Println("Rdset:", thash)
	Myhash := sha256.New()
	for i:=0;i<len(RdSet);i++{
		s := RdSet[i]
		//fmt.Println(i,RdSet[i])
		itemhash := Myhash.Sum([]byte(s))
		strhash := hex.EncodeToString(itemhash)
		//fmt.Println(i,strhash)
		if (strhash == thash){
			fmt.Println("we get it")
			return true
		}
	}
    return false
}

func createData(){
	ldata := LogisticsRd{}
	ldata.status=1
	ldata.stkey = generateIndex()
	//fmt.Println("stkey=:",ldata.stkey)
	sData := generateSdata()
	cipherBytes := EncryptSdata(sData) //LC encrtypt the data with public key of ES
	ldata.CTcontent = hex.EncodeToString(cipherBytes)//LC encrtypt the data with public key of ES
	fmt.Println("CTContent",ldata.CTcontent,"stkey",ldata.stkey,ldata.status)
	storeDataToCS(ldata)
}

func main(){
	//createData()
	start := time.Now().UnixNano()
	sData := generateSdata()  //target record
	cipherBytes := EncryptSdata(sData)
	Myhash := sha256.New()
	res := Myhash.Sum(cipherBytes)
	stkey := generateIndex()
	dataAudit(hex.EncodeToString(res),stkey)
	end := time.Now().UnixNano()
	fmt.Printf("runtime: %v (ns)\n", end-start)
}