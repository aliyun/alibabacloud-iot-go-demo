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

package source_proxy

import (
	"errors"
	"io"
	"iot-lp-demo-go/src/aliyun.com/iot/securetunnel/protocol"
	"log"
	"net"
	"sync"
)

type SourceProxy struct {
	TunnelId             string
	SecureTunnel         *protocol.SecureTunnel
	PortOfService        map[string]string
	ConnOfSession        map[string]*net.TCPConn
	tcpListenerOfService map[string]*net.TCPListener
	state                uint8 //0：关闭；1：开启
	stateLock            sync.Mutex
}

func (sourceProxy *SourceProxy) Close() error {
	if sourceProxy == nil {
		log.Fatalln("sourceProxy should not be nil")
	}
	sourceProxy.stateLock.Lock()
	defer sourceProxy.stateLock.Unlock()
	if sourceProxy.state == 0 {
		log.Println("sourceProxy state is closed")
	} else {
		sourceProxy.closeProxyListener()
		log.Printf("sourceProxy.closeProxyListener")
		if sourceProxy.SecureTunnel != nil {
			sourceProxy.SecureTunnel.Disconnect()
			log.Printf("sourceProxy.SecureTunnel.Disconnect")
		}
		sourceProxy.state = 0
	}

	return nil
}

func (sourceProxy *SourceProxy) Start() error {
	if sourceProxy == nil {
		return errors.New("sourceProxy should not be nil")
	}
	if len(sourceProxy.TunnelId) == 0 {
		return errors.New("sourceProxy.TunnelId should no be empty")
	}
	if sourceProxy.SecureTunnel == nil {
		return errors.New("sourceProxy.SecureTunnel should no be nil")
	}

	sourceProxy.stateLock.Lock()
	defer sourceProxy.stateLock.Unlock()

	if sourceProxy.state == 1 {
		log.Println("sourceProxy state is open")
	} else {
		sourceProxy.ConnOfSession = make(map[string]*net.TCPConn)
		sourceProxy.tcpListenerOfService = make(map[string]*net.TCPListener)

		sourceProxy.SecureTunnel.DataTransferFrameHandler = sourceProxy.HandleDataTransport
		//if len(sourceProxy.ConnOfSession) != 0 {
		//	log.Fatalln("sourceProxy.ConnOfSession should be empty")
		//}
		if len(sourceProxy.PortOfService) == 0 {
			return errors.New("sourceProxy.PortOfService should not be empty")
		}

		err := sourceProxy.SecureTunnel.Connect()
		log.Printf("sourceProxy.SecureTunnel connection status:%t\n", sourceProxy.SecureTunnel.IsConnected())
		if err != nil {
			return err
		}
		if !sourceProxy.SecureTunnel.IsConnected() {
			return errors.New("sourceProxy.SecureTunnel connection status should be connected")
		}

		err = sourceProxy.startProxyListener()
		if err != nil {
			return err
		}
		sourceProxy.state = 1
		log.Printf("tunnel :%s source proxy started successfully.\n", sourceProxy.TunnelId)
	}

	return nil
}

func (sourceProxy *SourceProxy) startProxyListener() error {
	for service := range sourceProxy.PortOfService {
		port := sourceProxy.PortOfService[service]
		go sourceProxy.processSingleListener(sourceProxy.SecureTunnel, service, port)
	}
	return nil
}

func (sourceProxy *SourceProxy) processSingleListener(secureTunnel *protocol.SecureTunnel, service string, port string) {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:"+port)
	listen, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Fatalln("tcp listener start failed. port:"+port, err)
	}
	if listen == nil {
		log.Fatalln("tcp listener start failed. port:" + port + " Listener is nil")
	}
	sourceProxy.tcpListenerOfService[service] = listen

	for {
		accept, err := listen.AcceptTCP()
		if err != nil {
			log.Println("listen accept error", err)
			return
		}
		if accept == nil {
			log.Fatalln("accept should not be nil")
		}

		go sourceProxy.processSourceClient(secureTunnel, service, accept)
	}
}

func (sourceProxy *SourceProxy) processSourceClient(secureTunnel *protocol.SecureTunnel, service string, sourceClient *net.TCPConn) {
	sessionId, err := secureTunnel.StartSession(service)
	log.Printf("new session of secure tunnel, for service:%s, sessionId:%s, err:%s\n", service, sessionId, err)
	if err != nil {
		return
	}
	sourceProxy.ConnOfSession[sessionId] = sourceClient

	var buffer [1024]byte
	for {
		length, err := sourceClient.Read(buffer[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Println(" sourceClient.Read error", err)
			break
		}
		if length == 0 {
			continue
		}
		err = secureTunnel.SendData(sessionId, buffer[0:length])
		if err != nil {
			log.Println("secureTunnel.SendData error", err)
			break
		}
	}
	err = secureTunnel.CloseSession(sessionId)
	if err != nil {
		log.Println("secureTunnel.CloseSession(sessionId) err", err)
	}
	delete(sourceProxy.ConnOfSession, sessionId)
}

func (sourceProxy *SourceProxy) HandleDataTransport(frame *protocol.TunnelFrame) {
	sessionId := frame.FrameHeader.SessionId
	log.Printf("Proxy receive data transport frame. sessionId:%s frameId:%d\n", sessionId, frame.FrameHeader.FrameId)

	conn := sourceProxy.ConnOfSession[sessionId]
	if conn == nil {
		log.Fatalln("sourceProxy.ConnOfSession[sessionId] should not be nil")
	}
	var totalWrite = 0

	frameLength := len(frame.Payload)

	for {
		write, err := conn.Write(frame.Payload[totalWrite:])
		if err != nil {
			log.Fatalln("(*conn).Write(frame.Payload) err", err)
		}
		totalWrite += write
		if totalWrite >= frameLength {
			break
		}
	}
}

func (sourceProxy *SourceProxy) closeProxyListener() {
	for sessionId, tcpConn := range sourceProxy.ConnOfSession {
		err := tcpConn.Close()
		if err != nil {
			log.Println("tcpConn.Close error when closeProxyListener", err)
		}
		err = sourceProxy.SecureTunnel.CloseSession(sessionId)
		if err != nil {
			log.Println("CloseSession error when closeProxyListener", err)
		}
		delete(sourceProxy.ConnOfSession, sessionId)
	}
	for service, listener := range sourceProxy.tcpListenerOfService {
		if listener != nil {
			log.Println("closeProxyListener close ProxyListener service:" + service)
			err := listener.Close()
			if err != nil {
				log.Println("tcpConn.Close error when closeProxyListener", err)
			}

			delete(sourceProxy.tcpListenerOfService, service)
		}
	}
}
