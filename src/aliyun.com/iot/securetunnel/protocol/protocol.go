/*
*Copyright (c) 2021, Alibaba Group;
*Licensed under the Apache License, Version 2.0 (the "License");
*you may not use this file except in compliance with the License.
*You may obtain a copy of the License at
*      http://www.apache.org/licenses/LICENSE-2.0
*Unless required by applicable law or agreed to in writing, software
*distributed under the License is distributed on an "AS IS" BASIS,
*WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*See the License for the specific language governing permissions and
*limitations under the License.
 */

package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/emirpasic/gods/sets/hashset"
	"github.com/gorilla/websocket"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	/*
	 * the frame type for response
	 */
	CommonResponse = 1
	/*
	 * the frame type for session creation
	 */
	SessionCreate = 2
	/*
	 * the frame type for session release
	 */
	SessionRelease = 3
	/*
	 * the frame type for data transfer
	 */
	DataTransport = 4

	MaxFramePayloadLength = 4 * 1024
)

const ProxyVersion = "source-proxy-go-v1.0"

type TunnelResponse struct {
	Code int32  `json:"code"`
	Msg  string `json:"msg"`
}

type SecureTunnel struct {
	TunnelId                 string
	AccessUrl                string
	AccessToken              string
	Host                     string
	Path                     string
	Port                     int
	Udi                      string
	DataTransferFrameHandler ReceivedTunnelFrameProcessor
	isConnected              bool
	wbConnection             *websocket.Conn
	frameId                  uint32
	mutex                    sync.Mutex
	callBackOfFrame          map[uint32]FrameCallbackHandler
	channelOfFrame           map[uint32]chan TunnelFrame
	sessionIds               *hashset.Set
	sendLock                 sync.Mutex
}

func (secureTunnel *SecureTunnel) Init() {
	secureTunnel.frameId = rand.Uint32()
	secureTunnel.callBackOfFrame = make(map[uint32]FrameCallbackHandler, 1)
	secureTunnel.channelOfFrame = make(map[uint32]chan TunnelFrame, 1)
	secureTunnel.sessionIds = hashset.New()
	go secureTunnel.startPing()
}

func (secureTunnel *SecureTunnel) startPing() {
	var ticker = time.NewTicker(time.Second * 30)
	for {
		select {
		case _ = <-ticker.C:
			secureTunnel.sendLock.Lock()
			if secureTunnel.isConnected {
				err := secureTunnel.wbConnection.WriteMessage(websocket.PingMessage, nil)
				if err != nil {
					log.Println("send ping frame err,", err)
					return
				}
				log.Println("send ping frame success")
			}
			secureTunnel.sendLock.Unlock()
		}
	}
}

type ReceivedTunnelFrameProcessor func(frame *TunnelFrame)

type FrameCallbackHandler func(uint32, *TunnelFrame)

func (secureTunnel *SecureTunnel) Connect() error {
	if secureTunnel.isConnected {
		return nil
	}

	addr := strings.Join([]string{secureTunnel.Host, strconv.Itoa(secureTunnel.Port)}, ":")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	u := url.URL{Scheme: "wss", Host: addr, Path: secureTunnel.Path}
	log.Printf("connecting to %s", u.String())

	requestHeader := http.Header{}
	requestHeader.Set("tunnel-access-token", secureTunnel.AccessToken)
	requestHeader.Set("subprotocol", "aliyun.iot.securetunnel-v1.1")
	requestHeader.Set("source-proxy-version", ProxyVersion)

	c, httpResponse, err := websocket.DefaultDialer.Dial(u.String(), requestHeader)
	if err != nil {
		log.Println("dial error ", httpResponse, err)
		return errors.New("dial error")
	}
	if httpResponse != nil && httpResponse.StatusCode != http.StatusSwitchingProtocols {
		return errors.New("httpResponse is nil or statusCode is not 101:upgrade")
	}
	if c == nil {
		return errors.New("conn.Conn should not be nil")
	}
	secureTunnel.wbConnection = c
	secureTunnel.isConnected = true
	go secureTunnel.handleReceivedMessage()
	return nil
}

func (secureTunnel *SecureTunnel) handleReceivedMessage() {
	for {
		if secureTunnel.wbConnection == nil {
			log.Fatalln("secure tunnel should be connected")
		}
		message, byteArray, err := secureTunnel.wbConnection.ReadMessage()
		if err != nil {
			log.Println("receive msg err", err)
			break
		}
		if message != websocket.BinaryMessage {
			log.Println("frame type from websocket should be binary")
			continue
		}
		if byteArray == nil {
			log.Println("byteArray from websocket is nil")
			continue
		}
		tunnelFrame := ParseFromByteArray(byteArray)
		secureTunnel.handleTunnelFrame(&tunnelFrame)
	}
}

func (secureTunnel *SecureTunnel) handleTunnelFrame(tunnelFrame *TunnelFrame) {
	if tunnelFrame == nil {
		log.Println("tunnelFrame should not be nil")
		return
	}
	if tunnelFrame.FrameHeader == nil {
		log.Println("tunnelFrame.FrameHeader should not be nil")
		return
	}
	frameIdStr := strconv.FormatUint(uint64(tunnelFrame.FrameHeader.FrameId), 10)
	log.Printf("tunnel:%s received tunnelFrame:%s\n", secureTunnel.TunnelId, tunnelFrame.ToString())

	switch tunnelFrame.FrameHeader.FrameType {
	case DataTransport:
		{
			log.Println("receive DataTransport frame, frameId:" + frameIdStr)
			if secureTunnel.DataTransferFrameHandler == nil {
				log.Printf("secureTunnel.dataTransferFrameHandler should not be nil")
			} else {
				secureTunnel.DataTransferFrameHandler(tunnelFrame)
			}
		}
	case SessionCreate:
		{
			log.Println("tunnel source should not receive SessionCreate frame, frameId:" + frameIdStr)
		}
	case SessionRelease:
		{
			log.Println("receive SessionRelease frame, frameId:" + frameIdStr + ". sessionId:" + tunnelFrame.FrameHeader.SessionId)
		}
	case CommonResponse:
		{
			log.Println("receive CommonResponse frame, frameId:" + frameIdStr)
			callbackHandler := secureTunnel.callBackOfFrame[tunnelFrame.FrameHeader.FrameId]
			if callbackHandler == nil {
				log.Println("there is no callback handler from response frame:" + frameIdStr)
			} else {
				callbackHandler(tunnelFrame.FrameHeader.FrameId, tunnelFrame)
			}
		}
	}
}

func (secureTunnel *SecureTunnel) IsConnected() bool {
	return secureTunnel.isConnected
}

func (secureTunnel *SecureTunnel) Disconnect() {
	if !secureTunnel.isConnected {
		return
	}
	connection := secureTunnel.wbConnection
	if connection == nil {
		log.Println("websocket connection is null for secure tunnel:" + secureTunnel.TunnelId)
		return
	}
	err := connection.Close()
	if err != nil {
		log.Fatal("the websocket of secure tunnel close error:"+secureTunnel.TunnelId, err)
	}
	log.Println("the websocket connection is closed successfully for secure tunnel:" + secureTunnel.TunnelId)
	secureTunnel.isConnected = false
}

func (secureTunnel *SecureTunnel) StartSession(serviceType string) (string, error) {
	frameId := secureTunnel.getNextFrameId()
	var header = TunnelFrameHeader{frameId, SessionCreate, serviceType, ""}

	var frame = TunnelFrame{
		FrameHeader: &header,
		Payload:     nil,
	}
	array, err := frame.toByteArray()
	if err != nil {
		log.Fatalln("frame.toByteArray error", err)
	}
	if array == nil {
		log.Fatalln("array should not be nil")
	}
	secureTunnel.sendLock.Lock()
	if secureTunnel.wbConnection != nil {
		err = secureTunnel.wbConnection.WriteMessage(websocket.BinaryMessage, array)
	}
	secureTunnel.sendLock.Unlock()

	channel := make(chan TunnelFrame)
	defer close(channel)
	secureTunnel.channelOfFrame[frameId] = channel
	secureTunnel.AddCallBackOfFrame(frameId, secureTunnel.WaitResponse)

	frame = <-channel
	payload := frame.Payload
	if len(payload) == 0 {
		log.Fatalln("the payload of frame should not be empty")
	}

	response := TunnelResponse{}
	err = json.Unmarshal(payload, &response)
	if err != nil {
		log.Fatalln("parse response of frame failed. err:", err)
	}
	if response.Code == 0 {
		return frame.FrameHeader.SessionId, nil
	}
	log.Printf("start session failed. errcode:%d errMsg:%s\n", response.Code, response.Msg)
	return "", errors.New(response.Msg)
}

func (secureTunnel *SecureTunnel) WaitResponse(frameId uint32, frame *TunnelFrame) {
	if frameId < 0 {
		log.Fatalln("frameId should not be less than 0")
	}

	channelOfFrame := secureTunnel.channelOfFrame[frameId]
	if channelOfFrame == nil {
		log.Fatalf("channel of frameId should not be nil. frameId:%d\n", frameId)
	}
	secureTunnel.sessionIds.Add(frame.FrameHeader.SessionId)
	channelOfFrame <- *frame
	return
}
func (secureTunnel *SecureTunnel) getNextFrameId() uint32 {
	secureTunnel.mutex.Lock()
	var frameId = secureTunnel.frameId
	if frameId == 0 {
		secureTunnel.frameId = 1
		frameId = 1
	}
	secureTunnel.frameId++
	secureTunnel.mutex.Unlock()
	return frameId
}

type CloseReason struct {
	code uint8
	msg  string
}

func (secureTunnel *SecureTunnel) CloseSession(sessionId string) error {
	contains := secureTunnel.sessionIds.Contains(sessionId)
	if !contains {
		log.Println("there is no session in this tunnel. sessionId:" + sessionId)
		return nil
	}
	var header = TunnelFrameHeader{secureTunnel.getNextFrameId(), SessionRelease, "", sessionId}
	closeReason := CloseReason{0, "source simulator close session."}
	reasonBytes, err := json.Marshal(closeReason)
	if err != nil {
		log.Fatalln("json.Marshal error", err)
	}
	if len(reasonBytes) == 0 {
		log.Fatalln("reasonBytes len should not be 0")
	}

	var frame = TunnelFrame{
		FrameHeader: &header,
		Payload:     reasonBytes,
	}
	array, err := frame.toByteArray()
	if err != nil {
		return err
	}
	if array == nil {
		return fmt.Errorf("array should not be nil")
	}
	secureTunnel.sendLock.Lock()
	if secureTunnel.wbConnection != nil {
		err = secureTunnel.wbConnection.WriteMessage(websocket.BinaryMessage, array)
	}
	secureTunnel.sendLock.Unlock()
	secureTunnel.sessionIds.Remove(sessionId)
	return err
}

func (secureTunnel *SecureTunnel) SendData(sessionId string, data []byte) error {
	var header = TunnelFrameHeader{secureTunnel.getNextFrameId(), DataTransport, "", sessionId}
	var frame = TunnelFrame{
		FrameHeader: &header,
		Payload:     data,
	}

	array, err := frame.toByteArray()
	if err != nil {
		return err
	}
	if array == nil {
		return fmt.Errorf("array should not be nil")
	}

	secureTunnel.sendLock.Lock()
	if secureTunnel.wbConnection != nil {
		err = secureTunnel.wbConnection.WriteMessage(websocket.BinaryMessage, array)
	}
	secureTunnel.sendLock.Unlock()

	log.Printf("SecureTunnel SendData success:%t", err == nil)
	return err
}

func (secureTunnel *SecureTunnel) AddCallBackOfFrame(frameId uint32, callback FrameCallbackHandler) {
	secureTunnel.callBackOfFrame[frameId] = callback
}

type TunnelFrame struct {
	FrameHeader *TunnelFrameHeader
	Payload     []byte
}

func (tunnelFrame *TunnelFrame) ToString() string {
	if tunnelFrame == nil {
		return "nil"
	}
	return fmt.Sprintf("header:%s,payload length:%d", tunnelFrame.FrameHeader.ToString(), len(tunnelFrame.Payload))
}

type TunnelFrameHeader struct {
	FrameId     uint32 `json:"frame_id"`
	FrameType   uint8  `json:"frame_type"`
	ServiceType string `json:"service_type"`
	SessionId   string `json:"session_id"`
}

func (header *TunnelFrameHeader) ToString() string {
	if header == nil {
		return "nil"
	}
	return fmt.Sprintf("FrameId:%d,FrameType:%d,ServiceType:%s,SessionId:%s", header.FrameId, header.FrameType, header.ServiceType, header.ServiceType)
}

func (tunnelFrame *TunnelFrame) toByteArray() ([]byte, error) {
	if tunnelFrame == nil {
		return nil, fmt.Errorf("tunnelFrame should not be nil pointer")
	}
	if tunnelFrame.FrameHeader == nil {
		return nil, fmt.Errorf("tunnelFrame.FrameHeader should not be nil pointer")
	}
	if tunnelFrame.FrameHeader.FrameId == 0 {
		return nil, fmt.Errorf("tunnelFrame.FrameHeader.FrameId should not be 0")
	}
	if tunnelFrame.FrameHeader.FrameType == 0 {
		return nil, fmt.Errorf("tunnelFrame.FrameHeader.FrameType should not be 0")
	}
	if tunnelFrame.Payload != nil && len(tunnelFrame.Payload) > MaxFramePayloadLength {
		return nil, fmt.Errorf("the length of tunnelFrame.FrameHeader.Payload should not be more than %d", MaxFramePayloadLength)
	}
	headerBytes, err := json.Marshal(tunnelFrame.FrameHeader)
	if err != nil {
		return nil, err
	}
	if headerBytes == nil {
		return nil, fmt.Errorf("headerBytes should not be nil")
	}
	headerLength := len(headerBytes)
	if headerLength > 2048 {
		log.Fatalln("headerLength should not be more than 2048")
	}
	var tunnelFrameByteArray = make([]byte, 2+len(tunnelFrame.Payload)+headerLength)
	headerLengthBytes := IntToBytes(headerLength)

	copy(tunnelFrameByteArray, headerLengthBytes)
	copy(tunnelFrameByteArray[2:], headerBytes)
	copy(tunnelFrameByteArray[2+headerLength:], tunnelFrame.Payload)

	return tunnelFrameByteArray, nil
}

func ParseFromByteArray(data []byte) TunnelFrame {
	if data == nil || len(data) == 0 {
		log.Fatalln("data should not be empty")
	}
	if len(data) < 2 {
		log.Fatalln("the len of data should be more than 2")
	}
	headerLength := BytesToInt(data[0:2])
	if headerLength <= 0 {
		log.Fatalln("headerLength should not be less than 1")
	}
	if 2+headerLength > len(data) {
		log.Fatalln("2 + headerLength should not be more than len(data)")
	}

	frameHeader := TunnelFrameHeader{}
	err := json.Unmarshal(data[2:2+headerLength], &frameHeader)
	if err != nil {
		log.Fatalln("parse tunnel frame header err", err)
	}
	return TunnelFrame{&frameHeader, data[2+headerLength:]}
}

//整形转换成字节
func IntToBytes(n int) []byte {
	x := int16(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	err := binary.Write(bytesBuffer, binary.BigEndian, x)
	if err != nil {
		return nil
	}
	return bytesBuffer.Bytes()
}

//字节转换成整形
func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)
	var x int16
	err := binary.Read(bytesBuffer, binary.BigEndian, &x)
	if err != nil {
		return 0
	}
	return int(x)
}
