package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

type PayloadStruct struct {
	EventTime time.Time `json:"eventTime"`
	RecordId  string    `json:"recordId"`
	Payload   string    `json:"payload"`
	IsHash    string    `json:"isHash"`
	OwnerId   string    `json:"ownerId"`
	IsUser    string    `json:"isUser"`
}

type PayloadPrivateStruct struct {
	RecordId  string `json:"recordId"`
	OwnerName string `json:"ownerName"`
}

type AuditStruct struct {
	AuditTime   time.Time `json:"auditTime"`
	RecordId    string    `json:"recordId"`
	AuditResult string    `json:"auditResult"`
	VerifierId  string    `json:"verifierId"`
}

type RecordSharedWith struct {
	EventTime        time.Time `json:"eventTime"`
	RecordId         string    `json:"recordId"`
	RecordName       string    `json:"recordName"`
	RecordOwnerId    string    `json:"recordOwnerId"`
	RecordSharedWith []string  `json:"recordSharedWith"`
	IsAuthenticated  string    `json:"isAuthenticated"`
	IsFile           string    `json:"isFile"`
	IsDeleted        string    `json:"isDeleted"`
}

type ClaimStruct struct {
	EventTime   time.Time `json:"eventTime"`
	RecordId    string    `json:"recordId"`
	ClaimAmount string    `json:"claimAmount"`
	ClaimIssuer string    `json:"claimIssuer"`
	IsClaim     string    `json:"isClaim"`
}

// SimpleChaincode example simple Chaincode implementation
type SimpleChaincode struct {
}

// ============================================================================================================================
// Main
// ============================================================================================================================
func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err)
	}

}

// ============================================================================================================================
// Init - reset all the things
// ============================================================================================================================
func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	fmt.Println("Init done ")
	return shim.Success(nil)
}

// ============================================================================================================================
// Invoke - Our entry point for Invocations
// ============================================================================================================================
func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()
	fmt.Println("invoke is running " + function)
	action := args[0]
	fmt.Println("invoke action " + action)
	fmt.Println(args)
	if action == "init" { //initialize the chaincode state, used as reset
		return t.Init(stub)
	} else if action == "commit" {
		return t.EventHandler(stub, args)
	} else if action == "commitPrivate" {
		return t.EventHandlerPrivate(stub, args)
	} else if action == "readPrivate" {
		return t.readUserPrivateDetails(stub, args)
	} else if action == "query" {
		return t.Query(stub, args)
	} else if action == "queryPrivate" {
		return t.QueryPrivate(stub, args)
	} else if action == "audit" {
		return t.AuditEventHandler(stub, args)
	} else if action == "upload" {
		return t.UploadEventHandler(stub, args)
	} else if action == "modify" {
		return t.ModifyEventHandler(stub, args)
	} else if action == "claim" {
		return t.ClaimEventHandler(stub, args)
	} else if action == "authenticate" {
		return t.AuthenticateEventHandler(stub, args)
	} else if action == "delete" {
		return t.DeleteEventHandler(stub, args)
	}

	fmt.Println("invoke did not find func: " + action) //error

	return shim.Error("Received unknown function")
}

// ===== Example: Ad hoc rich query ========================================================
// Only available on state databases that support rich query (e.g. CouchDB)
// =========================================================================================
func (t *SimpleChaincode) Query(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	queryString := args[1]

	queryResults, err := getQueryResultForQueryString(stub, queryString)
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(queryResults)
}

// ===== Example: Ad hoc rich query ========================================================
// Only available on state databases that support rich query (e.g. CouchDB)
// =========================================================================================
func (t *SimpleChaincode) QueryPrivate(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	queryString := args[1]

	queryResults, err := getQueryPrivateResultForQueryString(stub, queryString)
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(queryResults)
}

// =========================================================================================
// getQueryResultForQueryString executes the passed in query string.
// Result set is built and returned as a byte array containing the JSON results.
// =========================================================================================
func getQueryPrivateResultForQueryString(stub shim.ChaincodeStubInterface, queryString string) ([]byte, error) {

	//fmt.Println("GetQueryResultForQueryString() : getQueryResultForQueryString queryString:\n%s\n", queryString)

	resultsIterator, err := stub.GetPrivateDataQueryResult("collectionUserPrivateDetails", queryString)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()
	fmt.Println(resultsIterator)
	// buffer is a JSON array containing QueryRecords
	var buffer bytes.Buffer
	buffer.WriteString("[")

	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		// Add a comma before array members, suppress it for the first array member
		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		queryResponseStr := string(queryResponse.Value)
		fmt.Println(queryResponseStr)
		buffer.WriteString(queryResponseStr)
		bArrayMemberAlreadyWritten = true
	}
	buffer.WriteString("]")

	//fmt.Println("GetQueryResultForQueryString(): getQueryResultForQueryString queryResult:\n%s\n", buffer.String())

	return buffer.Bytes(), nil
}

// =========================================================================================
// getQueryResultForQueryString executes the passed in query string.
// Result set is built and returned as a byte array containing the JSON results.
// =========================================================================================
func getQueryResultForQueryString(stub shim.ChaincodeStubInterface, queryString string) ([]byte, error) {

	//fmt.Println("GetQueryResultForQueryString() : getQueryResultForQueryString queryString:\n%s\n", queryString)

	resultsIterator, err := stub.GetQueryResult(queryString)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()
	fmt.Println(resultsIterator)
	// buffer is a JSON array containing QueryRecords
	var buffer bytes.Buffer
	buffer.WriteString("[")

	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		// Add a comma before array members, suppress it for the first array member
		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		queryResponseStr := string(queryResponse.Value)
		fmt.Println(queryResponseStr)
		buffer.WriteString(queryResponseStr)
		bArrayMemberAlreadyWritten = true
	}
	buffer.WriteString("]")

	//fmt.Println("GetQueryResultForQueryString(): getQueryResultForQueryString queryResult:\n%s\n", buffer.String())

	return buffer.Bytes(), nil
}

func (t *SimpleChaincode) EventHandler(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error
	var owner string
	ishash := args[1]
	uniqueid := args[2]
	currentTime := time.Now().Local()
	inputStr := []byte(args[3])
	isUser := "true"

	if args[4] != "" {
		owner = args[4]
	} else {
		owner = ""
	}

	fmt.Printf("Entering Invoke......\n")
	var payloadValue string

	if ishash == "true" {
		payload := sha256.New()
		payload.Write(inputStr)
		fmt.Printf("%x", payload.Sum(nil))
		payloadValue = base64.URLEncoding.EncodeToString(payload.Sum(nil))
	} else if ishash == "false" {
		payloadValue = args[3]
	}

	payloadDataEvent := &PayloadStruct{
		currentTime,
		uniqueid,
		payloadValue,
		ishash,
		owner,
		isUser}

	payloadDataEventJSONasBytes, err := json.Marshal(payloadDataEvent)

	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(stub.GetTxID(), payloadDataEventJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (t *SimpleChaincode) EventHandlerPrivate(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	recordId := args[1]
	ownerName := args[2]

	payloadPrivateStruct := &PayloadPrivateStruct{
		recordId,
		ownerName}
	payloadPrivateDataEventJSONasBytes, err := json.Marshal(payloadPrivateStruct)

	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutPrivateData("collectionUserPrivateDetails", recordId, payloadPrivateDataEventJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (t *SimpleChaincode) readUserPrivateDetails(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var recordId, jsonResp string
	var err error

	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting name of the marble to query")
	}

	recordId = args[1]
	valAsbytes, err := stub.GetPrivateData("collectionUserPrivateDetails", recordId) //get the marble private details from chaincode state
	if err != nil {
		jsonResp = "{\"Error\":\"Failed to get private details for " + recordId + ": " + err.Error() + "\"}"
		return shim.Error(jsonResp)
	} else if valAsbytes == nil {
		jsonResp = "{\"Error\":\"Marble private details does not exist: " + recordId + "\"}"
		return shim.Error(jsonResp)
	}

	return shim.Success(valAsbytes)
}

func (t *SimpleChaincode) AuditEventHandler(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error

	a_uniqueid := args[1]
	a_time := time.Now().Local()
	a_verifier := args[3]
	a_verifyResult := args[6]

	fmt.Printf("Entering Invoke......\n")

	AuditEvent := &AuditStruct{
		a_time,
		a_uniqueid,
		a_verifyResult,
		a_verifier}

	AuditEventJSONasBytes, err := json.Marshal(AuditEvent)

	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(stub.GetTxID(), AuditEventJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (t *SimpleChaincode) ClaimEventHandler(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error

	a_uniqueid := args[1]
	a_time := time.Now().Local()
	a_claimAmount := args[2]
	a_claimIssuer := args[3]
	a_isClaim := "true"

	fmt.Printf("Entering Invoke......\n")

	ClaimEvent := &ClaimStruct{
		a_time,
		a_uniqueid,
		a_claimAmount,
		a_claimIssuer,
		a_isClaim}

	ClaimEventJSONasBytes, err := json.Marshal(ClaimEvent)

	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(stub.GetTxID(), ClaimEventJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (t *SimpleChaincode) UploadEventHandler(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error
	var err1 error
	var owner string
	var sharedWith []string
	ishash := args[1]
	uniqueid := args[2]
	currentTime := time.Now().Local()
	inputStr := []byte(args[3])
	isFile := "true"
	recordName := args[5]
	isAuthenticated := "false"
	isUser := "false"
	isDeleted := "false"

	if args[4] != "" {
		owner = args[4]
	} else {
		owner = ""
	}

	sharedWith = append(sharedWith, owner)

	fmt.Printf("Entering Invoke......\n")
	var payloadValue string

	if ishash == "true" {
		payload := sha256.New()
		payload.Write(inputStr)
		fmt.Printf("%x", payload.Sum(nil))
		payloadValue = base64.URLEncoding.EncodeToString(payload.Sum(nil))
	} else if ishash == "false" {
		payloadValue = args[3]
	}

	payloadDataEvent := &PayloadStruct{
		currentTime,
		uniqueid,
		payloadValue,
		ishash,
		owner,
		isUser}

	recordSharedWithEvent := &RecordSharedWith{
		currentTime,
		uniqueid,
		recordName,
		owner,
		sharedWith,
		isAuthenticated,
		isFile,
		isDeleted}

	payloadDataEventJSONasBytes, err := json.Marshal(payloadDataEvent)

	recordSharedWithEventJSONasBytes, err1 := json.Marshal(recordSharedWithEvent)

	if err != nil {
		return shim.Error(err.Error())
	}

	if err1 != nil {
		return shim.Error(err1.Error())
	}

	err = stub.PutState(stub.GetTxID(), payloadDataEventJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}
	err1 = stub.PutState(uniqueid, recordSharedWithEventJSONasBytes)
	return shim.Success(nil)
}

func (t *SimpleChaincode) ModifyEventHandler(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error

	m_uniqueid := args[1]
	currentTime := time.Now().Local()
	isFile := "true"
	isDeleted := "false"
	fmt.Printf("Entering Invoke......\n")
	var sharedWith []string

	stringShared := args[4]
	sharedWith = strings.Split(stringShared, "@@##")

	recordSharedWithEvent := &RecordSharedWith{
		currentTime,
		m_uniqueid,
		args[2],
		args[3],
		sharedWith,
		args[5],
		isFile,
		isDeleted}

	recordSharedWithEventJSONasBytes, err := json.Marshal(recordSharedWithEvent)

	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(m_uniqueid, recordSharedWithEventJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (t *SimpleChaincode) AuthenticateEventHandler(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error

	m_uniqueid := args[1]
	currentTime := time.Now().Local()
	isFile := "true"
	isDeleted := "false"
	fmt.Printf("Entering Invoke......\n")
	var sharedWith []string

	stringShared := args[4]
	sharedWith = strings.Split(stringShared, "@@##")

	recordSharedWithEvent := &RecordSharedWith{
		currentTime,
		m_uniqueid,
		args[2],
		args[3],
		sharedWith,
		args[5],
		isFile,
		isDeleted}

	recordSharedWithEventJSONasBytes, err := json.Marshal(recordSharedWithEvent)

	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(m_uniqueid, recordSharedWithEventJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (t *SimpleChaincode) DeleteEventHandler(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error

	m_uniqueid := args[1]
	currentTime := time.Now().Local()
	isFile := "true"
	fmt.Printf("Entering Invoke......\n")
	var sharedWith []string

	stringShared := args[4]
	sharedWith = strings.Split(stringShared, "@@##")

	recordSharedWithEvent := &RecordSharedWith{
		currentTime,
		m_uniqueid,
		args[2],
		args[3],
		sharedWith,
		args[5],
		isFile,
		args[6]}

	recordSharedWithEventJSONasBytes, err := json.Marshal(recordSharedWithEvent)

	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(m_uniqueid, recordSharedWithEventJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}
