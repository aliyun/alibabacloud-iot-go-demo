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

package main

import (
	"encoding/json"
	"errors"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/widget"
	"iot-lp-demo-go/src/aliyun.com/iot/securetunnel/protocol"
	"iot-lp-demo-go/src/aliyun.com/iot/securetunnel/source_proxy"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type formStruct struct {
	ServiceType, LocalProxyPort string
}

func main() {
	// resultInfoChannel the channel for tip info update
	var resultInfoChannel = make(chan string, 10)
	defer close(resultInfoChannel)
	proxy := &source_proxy.SourceProxy{}

	//应用窗口定义
	a := app.New()
	win := a.NewWindow("the local proxy for the source end of device secure tunnel")
	//提示信息
	tipIIfo := widget.NewLabel("access info for the source end of secure tunnel")

	//访问端建连信息输入框
	infoInput := widget.NewMultiLineEntry()
	infoInput.PlaceHolder = "please type access info for the source end of source tunnel"

	//serviceType和本地端口的映射关系输入框
	var formValue formStruct
	//默认值
	formValue.ServiceType = "CUSTOM_SSH"
	formValue.LocalProxyPort = "6421"
	border := container.NewBorder(nil, nil, nil, nil, container.NewGridWithColumns(1, newFormWithData(binding.BindStruct(&formValue))))

	//状态及错误信息
	resultInfo := widget.NewLabel("")
	go func() {
		for {
			resultInfo.Text = <-resultInfoChannel
			resultInfo.Refresh()
		}
	}()

	//启动按钮
	startButton := buildStartButton(proxy, infoInput, &formValue, resultInfoChannel)

	//窗口布局
	win.SetContent(container.NewVBox(
		tipIIfo, infoInput, border, resultInfo,
		startButton,
		//关闭按钮
		widget.NewButton("close", func() {
			go closeProxy(proxy, resultInfoChannel)
		}),
	))

	win.Resize(fyne.NewSize(640, 460))
	//应用启动
	win.ShowAndRun()
}

func buildStartButton(proxy *source_proxy.SourceProxy, infoInput *widget.Entry, formStruct *formStruct, resultInfoChannel chan string) *widget.Button {
	return widget.NewButton("start", func() {
		conInfo := infoInput.Text
		err := checkSourceEndConInfo(conInfo)
		if err != nil {
			resultInfoChannel <- err.Error()
			return
		} else {
			resultInfoChannel <- ""
		}
		err = checkServiceTypeAndPort(formStruct.ServiceType, formStruct.LocalProxyPort)
		if err != nil {
			resultInfoChannel <- err.Error()
			return
		} else {
			resultInfoChannel <- ""
		}
		log.Printf("conInfo:%s serviceType:%s port:%s\n", conInfo, formStruct.ServiceType, formStruct.LocalProxyPort)
		go startProxy(proxy, conInfo, formStruct.ServiceType, formStruct.LocalProxyPort, resultInfoChannel)
	})
}

func newFormWithData(data binding.DataMap) *widget.Form {
	keys := data.Keys()
	items := make([]*widget.FormItem, len(keys))
	for i, k := range keys {
		data, err := data.GetItem(k)
		if err != nil {
			items[i] = widget.NewFormItem(k, widget.NewLabel(err.Error()))
		}
		items[i] = widget.NewFormItem(k, createBoundItem(data))
	}

	return widget.NewForm(items...)
}

func createBoundItem(v binding.DataItem) fyne.CanvasObject {
	switch val := v.(type) {
	case binding.Int:
		return widget.NewEntryWithData(binding.IntToString(val))
	case binding.String:
		return widget.NewEntryWithData(val)
	default:
		return widget.NewLabel("")
	}
}

func checkServiceTypeAndPort(serviceType string, portStr string) error {
	if serviceType == "" {
		return errors.New("serviceType can not be empty")
	}
	if portStr == "" {
		return errors.New("port can not be empty")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	if port <= 1024 {
		return errors.New("port should be greater than 1024")
	}
	if port >= 65535 {
		return errors.New("port should be less than 65535")
	}
	return nil
}

func checkSourceEndConInfo(info string) error {
	if info == "" {
		return errors.New("access info can not be empty")
	}

	tunnelInfo := struct {
		Token string `json:"token"`
		Url   string `json:"url"`
	}{}

	err := json.Unmarshal([]byte(info), &tunnelInfo)
	if err != nil {
		log.Println("access info format is invalid", err)
		return errors.New("access info format is invalid")
	}

	if tunnelInfo.Token == "" {
		log.Println("the token of access info should not be empty")
		return errors.New("the token of access info should not be empty")
	}

	if tunnelInfo.Url == "" {
		log.Println("the url of access info should not be empty")
		return errors.New("the url of access info should not be empty")
	}
	return nil
}

func closeProxy(proxy *source_proxy.SourceProxy, resultInfoChannel chan string) {
	err := proxy.Close()
	if err != nil {
		log.Println("closeProxy error", err)
	}

	resultInfoChannel <- "proxy closed"
}

func startProxy(proxy *source_proxy.SourceProxy, tunnelString string, serviceType string, port string, resultInfoChannel chan string) {
	tunnelInfo := struct {
		Token string `json:"token"`
		Url   string `json:"url"`
	}{}

	err := json.Unmarshal([]byte(tunnelString), &tunnelInfo)
	if err != nil {
		log.Fatalln("parse tunnel string info error", err)
	}

	var secureTunnel protocol.SecureTunnel

	parsedUrl, err := url.Parse(tunnelInfo.Url)
	if err != nil {
		resultInfoChannel <- "tunnelInfo is invalid"
		return
	}
	secureTunnel.Path = parsedUrl.Path
	secureTunnel.TunnelId = strings.TrimSuffix(strings.TrimPrefix(secureTunnel.Path, "/tunnel/"), "/source")
	secureTunnel.Host = parsedUrl.Host
	if parsedUrl.Port() != "" {
		secureTunnel.Port, _ = strconv.Atoi(parsedUrl.Port())
	} else {
		secureTunnel.Port = 443
	}
	secureTunnel.AccessToken = tunnelInfo.Token
	secureTunnel.Init()

	proxy.TunnelId = secureTunnel.TunnelId
	proxy.SecureTunnel = &secureTunnel
	proxy.PortOfService = make(map[string]string)
	proxy.PortOfService[serviceType] = port

	err = proxy.Start()
	if err != nil {
		log.Fatalln("proxy.Start() err", err)
	}
	resultInfoChannel <- "proxy started"
	time.Sleep(time.Hour * 1)
}
