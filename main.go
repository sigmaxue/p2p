// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a simple example demonstrating a Pion-to-Pion ICE connection
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pion/ice/v3"
	"github.com/pion/logging"
	"github.com/pion/randutil"
	"github.com/pion/stun/v2"
)

//nolint:gochecknoglobals
var (
	isControlling                 bool
	iceAgent                      *ice.Agent
	remoteAuthChannel             chan string
	localHTTPPort, remoteHTTPPort int
)
var remoteUfrag = ""
var remotePwd = ""
var localUfrag = ""
var localPwd = ""
var localCandidate []string

type SDP struct {
	ufrag     string   `json:"ufrag"`
	pwd       string   `json:"pwd"`
	candidate []string `json:"candidate"`
}

var sdp SDP

func MarshalSdp(sdp SDP) string {
	out := fmt.Sprintf("ufrag:\n%s\n", sdp.ufrag)
	out += fmt.Sprintf("pwd:\n%s\n", sdp.pwd)
	for _, v := range sdp.candidate {
		out += fmt.Sprintf("candidate:\n%s\n", v)
	}

	fmt.Println("MarshalSdp:", out)
	return out
}
func UnMarshalSdp(txt string) SDP {
	//fmt.Println("Raw: ", txt)
	var s SDP
	scanner := bufio.NewReader(strings.NewReader(txt))
	line, _, err := scanner.ReadLine()

	if strings.Contains(string(line), "ufrag:") {
		ufrag, _, _ := scanner.ReadLine()
		s.ufrag = string(ufrag)
	}
	line, _, _ = scanner.ReadLine()
	if strings.Contains(string(line), "pwd:") {
		pwd, _, _ := scanner.ReadLine()
		s.pwd = string(pwd)
	}
	for {
		line, _, err = scanner.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
		}
		if strings.Contains(string(line), "candidate:") {
			candidate, _, _ := scanner.ReadLine()
			s.candidate = append(s.candidate, string(candidate))
		}
	}
	fmt.Println("UnMarshalSdp:", s)
	return s
}

// HTTP Listener to get ICE Credentials from remote Peer
func remoteAuth(w http.ResponseWriter, r *http.Request) {
	var err error
	if err = r.ParseForm(); err != nil {
		panic(err)
	}

	// 反序列化为数据结构
	var sdpr SDP
	sdpr = UnMarshalSdp(r.PostForm["sdp"][0])
	for _, v := range sdpr.candidate {
		fmt.Printf("Remote candidate: %s\n", v)
		c, err := ice.UnmarshalCandidate(v)
		if err != nil {
			panic(err)
		}

		if err := iceAgent.AddRemoteCandidate(c); err != nil { //nolint:contextcheck
			panic(err)
		}
	}
	// 序列化为 JSON 字符串
	jsonData := MarshalSdp(sdp)
	if err != nil {
		fmt.Println("Failed to serialize:", err)
		return
	}
	// 构建 HTTP 响应
	response := jsonData
	// 设置响应头
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", fmt.Sprint(len(response)))
	w.Write([]byte(response))

	remoteAuthChannel <- sdpr.ufrag
	remoteAuthChannel <- sdpr.pwd
}

func main() { //nolint
	var (
		err  error
		conn *ice.Conn
	)

	remoteAuthChannel = make(chan string, 3)
	flag.BoolVar(&isControlling, "controlling", false, "is ICE Agent controlling")
	sdpip := flag.String("ip", "1.1.1.1", "http remote ip")
	flag.Parse()

	if isControlling {
		localHTTPPort = 9000
	} else {
		remoteHTTPPort = 9000
	}

	http.HandleFunc("/remoteAuth", remoteAuth)
	go func() {
		if err = http.ListenAndServe(fmt.Sprintf(":%d", localHTTPPort), nil); err != nil { //nolint:gosec
			panic(err)
		}
	}()

	// 创建一个 UDP 连接
	udpconn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 9000, IP: net.IPv4(0, 0, 0, 0)})
	if err != nil {
		fmt.Println("Failed to create UDP connection:", err)
		return
	}
	defer udpconn.Close()

	log := logging.NewDefaultLoggerFactory()
	log.DefaultLogLevel = logging.LogLevelError
	log.DefaultLogLevel = logging.LogLevelTrace

	//mux := ice.NewUDPMuxDefault(ice.UDPMuxParams{UDPConn: udpconn})

	udpMuxSrflx := ice.NewUniversalUDPMuxDefault(ice.UniversalUDPMuxParams{
		UDPConn: udpconn,
	})

	cfg := &ice.AgentConfig{
		//UDPMux: mux,
		UDPMuxSrflx:   udpMuxSrflx,
		NetworkTypes:  []ice.NetworkType{ice.NetworkTypeUDP4},
		LoggerFactory: log,
		Urls: []*stun.URI{
			{
				Scheme: stun.SchemeTypeSTUN,
				Host:   *sdpip,
				Port:   9000,
				Proto:  stun.ProtoTypeUDP,
			},
			// {
			// 	Scheme:   stun.SchemeTypeSTUN,
			// 	Host:     "stun.l.google.com",
			// 	Port:     19302,
			// 	Proto:    stun.ProtoTypeUDP,
			// },
		},
	}
	iceAgent, err = ice.NewAgent(cfg)
	if err != nil {
		panic(err)
	}

	// When we have gathered a new ICE Candidate send it to the remote peer
	if err = iceAgent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			return
		}
		localCandidate = append(localCandidate, c.Marshal())
		sdp.candidate = localCandidate
		fmt.Println(c.Marshal())
	}); err != nil {
		panic(err)
	}

	// Get the local auth details and send to remote peer
	localUfrag, localPwd, err = iceAgent.GetLocalUserCredentials()
	if err != nil {
		panic(err)
	}
	sdp.ufrag = localUfrag
	sdp.pwd = localPwd

	// When ICE Connection state has change print to stdout
	if err = iceAgent.OnConnectionStateChange(func(c ice.ConnectionState) {
		fmt.Printf("ICE Connection State has changed: %s\n", c.String())
	}); err != nil {
		panic(err)
	}

	// Start the ICE Agent. One side must be controlled, and the other must be controlling
	if err = iceAgent.GatherCandidates(); err != nil {
		panic(err)
	}

	if isControlling {
		fmt.Println("Local Agent is controlling")

		remoteUfrag = <-remoteAuthChannel
		remotePwd = <-remoteAuthChannel
		fmt.Printf("%s => %s \n", remoteUfrag, remotePwd)

		conn, err = iceAgent.Accept(context.TODO(), remoteUfrag, remotePwd)
		if err != nil {
			panic(err)
		}

	} else {
		fmt.Println("Local Agent is controlled")
		fmt.Print("Press 'Enter' when both processes have started")
		if _, err = bufio.NewReader(os.Stdin).ReadBytes('\n'); err != nil {
			panic(err)
		}

		fmt.Println("SDP", sdp)
		// 序列化为 JSON 字符串
		response, err := http.PostForm(fmt.Sprintf("http://%s:%d/remoteAuth", *sdpip, remoteHTTPPort), //nolint
			url.Values{
				"sdp": {MarshalSdp(sdp)},
				//"ufrag": {localUfrag},
				//"pwd":   {localPwd},
				//"candidate": {localCandidate},
			})
		if err != nil {
			panic(err)
		}
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Println("Failed to read response body:", err)
			return
		}
		// 反序列化为数据结构
		var sdpr SDP
		sdpr = UnMarshalSdp(string(body))
		remoteUfrag = sdpr.ufrag
		remotePwd = sdpr.pwd
		//candidate := headers["X-Candidate"][0]
		fmt.Printf("Remote ufrag: %s => pwd: %s \n", remoteUfrag, remotePwd)

		for _, v := range sdpr.candidate {
			fmt.Printf("Client Remote candidate: %s\n", v)
			c0, err := ice.UnmarshalCandidate(v)
			if err != nil {
				panic(err)
			}

			if err := iceAgent.AddRemoteCandidate(c0); err != nil { //nolint:contextcheck
				panic(err)
			}
		}
		conn, err = iceAgent.Dial(context.TODO(), remoteUfrag, remotePwd)
		if err != nil {
			panic(err)
		}
	}
	// 打印本地地址和远程地址
	localAddr := conn.LocalAddr()
	remoteAddr := conn.RemoteAddr()

	fmt.Println("Local address:", localAddr)
	fmt.Println("Remote address:", remoteAddr)

	// Send messages in a loop to the remote peer
	go func() {
		for {
			time.Sleep(time.Second * 3)

			val, err := randutil.GenerateCryptoRandomString(15, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
			if err != nil {
				panic(err)
			}
			if _, err = conn.Write([]byte(val)); err != nil {
				panic(err)
			}

			//fmt.Printf("Sent: '%s'\n", val)
		}
	}()

	// Receive messages in a loop from the remote peer
	buf := make([]byte, 1500)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			panic(err)
		}
		fmt.Print(".")
		//fmt.Printf("Received: '%s'\n", string(buf[:n]))
	}
}
