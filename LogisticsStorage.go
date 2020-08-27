package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	"strconv"
	"time"
)

type LogisticsRd struct{
	Pubk string
	Ps string
	CT_Rd string
	RdHash string
	utime int64
}

//var ESLogisticsMap = make(map[string][]LogisticsRd)

type LogisticsChaincode struct{}

func (t *LogisticsChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	fmt.Println("开始实例化链码......")
	// 获取参数
	// args := stub.GetStringArgs()
	_, args := stub.GetFunctionAndParameters()
	// 判断参数长度是否为2个
	if len(args) != 2 {
		return shim.Error("指定了错误的参数个数")
	}
	fmt.Println("保存数据......")
	// 通过调用PutState函数将数据保存在账本中
	err := stub.PutState(args[0], []byte(args[1]))
	if err != nil {
		return shim.Error("保存数据时发生错误")
	}
	fmt.Println("实例化链码成功")
	return shim.Success(nil)
}

// 对账本数据进行操作时被自动调用(query, invoke)
func (t *LogisticsChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	// 获取调用链码时传递的参数内容(包括要调用的函数名及参数)
	fun, args := stub.GetFunctionAndParameters()
	// 客户意图
	if fun == "query" {
		return queryRd(stub, args)
	}
	if fun == "storage"{
		return storage(stub, args)
	}
	return shim.Error("非法操作， 指定功能不能实现")
}

func objToStr(obj LogisticsRd) string{
	str_st := strconv.Itoa(int(obj.utime))
	str_pubk := obj.Pubk
	str_ps := obj.Ps
	str_ct := obj.CT_Rd
	str_hs := obj.RdHash
	return str_st+str_pubk+str_ps+str_ct+str_hs
}

func storage(stub shim.ChaincodeStubInterface, args []string) peer.Response{
	if len(args) !=4{
		return shim.Error("指定的参数错误， 必须且只能指定相应的Key")
	}
	utime := time.Now().UnixNano()
	Myhash := sha256.New()
	Rd := LogisticsRd{args[0],args[1],args[2],args[3],utime}
	index := Myhash.Sum([]byte(Rd.Pubk+Rd.Ps))
	strRd := objToStr(Rd)
	strIndex := string(index)
	err := stub.PutState(strIndex, []byte(strRd))
	if err != nil {
		return shim.Error("保存数据时发生错误")
	}
	fmt.Println("实例化链码成功")
	return shim.Success(nil)
}


func queryRd(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	// 检查传递的参数是否为1
	if len(args) != 1 {
		return shim.Error("指定的参数错误， 必须且只能指定相应的Key")
	}
	// 根据指定的Key调用GetState方法查询数据
	result, err := stub.GetState(args[0])
	if err != nil {
		return shim.Error("根据指定的 " + args[0] + " 查询数据时发生错误")
	}
	if result == nil {
		return shim.Error("根据指定的 " + args[0] + " 没有查询到相应的数据")
	}
	// 返回查询结果
	return shim.Success(result)
}

func main() {
	err := shim.Start(new(LogisticsChaincode))
	if err != nil {
		fmt.Printf("chaincode start failed: %v", err)
	}
}