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
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pion/ice/v3"
	"github.com/pion/logging"
	"github.com/pion/randutil"
	"github.com/pion/stun/v2"
)

//nolint:gochecknoglobals
var (
	iceAgent          *ice.Agent
	rufrag string
	rpwd   string
	err  error
	conn *ice.Conn
)
var hostCandidate = "4014588048 1 udp 2130706431 118.195.187.166 9000 typ host"

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
	iceAgent.Restart(sdp.ufrag,sdp.pwd)
	iceAgent.SetRemoteCredentials(sdpr.ufrag, sdpr.pwd)
	// Start the ICE Agent. One side must be controlled, and the other must be controlling
	if err = iceAgent.GatherCandidates(); err != nil {
		panic(err)
	}

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

}

func main() { //nolint
	//hostip := flag.String("ip", "1.1.1.1", "sdp host ip")
	remoteufrag := flag.String("remoteufrag", "psUOJWvuCSmEMrya", "sdp ufrag")
	remotepwd := flag.String("remotepwd", "cQnlwKvsvBYqhPFvJWcwQkCflGYlDBDv", "sdp pwd")
	ufrag := flag.String("ufrag", "omHaRLkERRNpethp", "sdp ufrag")
	pwd := flag.String("pwd", "bRLcmGIewhYyBQPolTrQbqvouPtkPeGn", "sdp pwd")
	localHTTPPort := flag.Int("port", 9000, "local listen port")
	flag.Parse()

	rufrag = *remoteufrag
	rpwd = *remotepwd
	http.HandleFunc("/remoteAuth", remoteAuth)
	go func() {
		if err = http.ListenAndServe(fmt.Sprintf(":%d", *localHTTPPort), nil); err != nil { //nolint:gosec
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

	mux := ice.NewUDPMuxDefault(ice.UDPMuxParams{UDPConn: udpconn})

	//udpMuxSrflx := ice.NewUniversalUDPMuxDefault(ice.UniversalUDPMuxParams{UDPConn: udpconn,})

	cfg := &ice.AgentConfig{
		//NAT1To1IPs:             []string{*hostip},
		//NAT1To1IPCandidateType: ice.CandidateTypeHost,
		LocalUfrag: *ufrag,
		LocalPwd: *pwd,
		UDPMux:                 mux,
		//UDPMuxSrflx:   udpMuxSrflx,
		NetworkTypes:  []ice.NetworkType{ice.NetworkTypeUDP4},
		LoggerFactory: log,
		Urls: []*stun.URI{
			{
				Scheme: stun.SchemeTypeSTUN,
				Host:   "stun.l.google.com",
				Port:   19302,
				Proto:  stun.ProtoTypeUDP,
			},
		},
	}
	iceAgent, err = ice.NewAgent(cfg)
	if err != nil {
		panic(err)
	}
	sdp.candidate = append(sdp.candidate, hostCandidate)
	// When we have gathered a new ICE Candidate send it to the remote peer
	if err = iceAgent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			return
		}
		fmt.Println(c.Marshal())
	}); err != nil {
		panic(err)
	}

	// Get the local auth details and send to remote peer
	localUfrag, localPwd, err := iceAgent.GetLocalUserCredentials()
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

	fmt.Println("Local Agent is controlling")

	conn, err = iceAgent.Accept(context.TODO(), *remoteufrag, *remotepwd)
	if err != nil {
		panic(err)
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
