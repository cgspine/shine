package main

import (
	"flag"
	"shine/shine"
	"log"
	"errors"
	"strconv"
	"net"
	"io"
	"encoding/binary"
	"os"
	"fmt"
)

// sock 协议：http://www.faqs.org/rfcs/rfc1928.html

type ServerCipher struct {
	Server string
	Cipher *shine.Cipher
}

var serverCipher *ServerCipher
var debug shine.DebugLog

var (
	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks command not supported")
)

const (
	socksVer5       = 5
	socksCmdConnect = 1
)

func main() {
	var configFile string
	var printVar bool
	flag.BoolVar(&printVar, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "config file")
	flag.BoolVar((*bool)(&debug), "debug", false, "debug")
	flag.Parse()
	if printVar {
		shine.PrintVer()
		os.Exit(0)
	}
	shine.SetDebug(debug)
	exist, err := shine.IsFileExist(configFile)
	if err != nil {
		log.Fatal(err)
	}
	if !exist {
		log.Fatal(errors.New("config file not exist"))
	}
	config, err := shine.ParseConfig(configFile)
	if err != nil {
		log.Fatal("parse config err: ", err)
	}
	log.Printf("config: %v", config)
	if !enoughOptions(config) {
		log.Fatal("missing some config field")
	}
	parseConfig(config)
	run("127.0.0.1:" + strconv.Itoa(config.LocalPort))
}

func enoughOptions(config *shine.Config) bool {
	return config.Server != "" && config.ServerPort != 0 &&
		config.LocalPort != 0 && config.Password != ""
}

func parseConfig(config *shine.Config) {
	hasPort := func(path string) bool {
		_, port, err := net.SplitHostPort(path)
		if err != nil {
			return false
		}
		return port != ""
	}

	method := config.Method
	cipher, err := shine.NewCipher(method, config.Password)
	if err != nil {
		log.Fatal("Failed generating cipher:", err)
	}
	if hasPort(config.Server) {
		log.Println("ignore server_port option for server: ", config.Server)
		serverCipher = &ServerCipher{config.Server, cipher}
	} else {
		serverCipher = &ServerCipher{net.JoinHostPort(config.Server, strconv.Itoa(config.ServerPort)), cipher}
	}
}

func run(client string) {
	ln, err := net.Listen("tcp", client)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("starting listen local sock5 at %v ...\n", client)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	debug.Printf("socks connect from %s\n", conn.RemoteAddr().String())
	closed := false
	defer func() {
		if !closed {
			conn.Close()
		}
	}()
	if err := handShake(conn); err != nil {
		log.Println("socks handshake:", err)
		return
	}
	rawAddress, address, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request:", err)
		return
	}
	// relay
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		debug.Println("send connection confirmation:", err)
		return
	}
	debug.Printf("getRequest: rawAddress = %v; address = %v", rawAddress, address)

	remote, err := connectToServer(rawAddress, address)
	if err != nil {
		log.Println(err)
		return
	}
	defer func() {
		if !closed {
			remote.Close()
		}
	}()
	go shine.PipeThenClose(conn, remote)
	shine.PipeThenClose(remote, conn)
	closed = true
	debug.Println("closed connection to", address)
}

//  步骤一：
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+
func handShake(con net.Conn) (err error) {
	const (
		idVer     = 0
		idNMethod = 1
	)

	shine.SetReadTimeout(con)
	// 目前sock协议最多256个方法， 加上ver和nmethod，最多需要258个字节
	buf := make([]byte, 258)
	var n int
	if n, err = io.ReadAtLeast(con, buf, idNMethod+1); err != nil {
		return
	}

	if buf[idVer] != socksVer5 {
		return errVer
	}

	nmethod := int(buf[idNMethod])
	msgLen := nmethod + 2
	if n == msgLen { // handshake done, common case
		// do nothing, jump directly to send confirmation
	} else if n < msgLen { // has more methods to read, rare case
		if _, err = io.ReadFull(con, buf[n:msgLen]); err != nil {
			return
		}
	} else { // error, should not get extra data
		return errAuthExtraData
	}
	// send confirmation: version 5, no authentication required
	_, err = con.Write([]byte{socksVer5, 0})
	return
}

// 步骤二：
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+

func getRequest(conn net.Conn) (rawAddress []byte, address string, err error) {
	const (
		idVar   = 0
		idCmd   = 1 // connect = x01; bind = x02; UDP ASSOCIATE = x03
		idAtyp  = 3 // address type of following address: IPV4 = 01; DOMAINNAME = 03; IPV6 = 04
		idIP0   = 4 // ip addres start index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
		lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)

	// 3(ver+cmd+rsv) + 1(addrType) + 1(lenByte) + 255(max length address) + 2(port)
	buf := make([]byte, 262)
	shine.SetReadTimeout(conn)
	var n int
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}
	if buf[idVar] != socksVer5 {
		err = errVer
		return
	}
	if buf[idCmd] != socksCmdConnect {
		err = errCmd
		return
	}

	reqLen := -1
	switch buf[idAtyp] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddrType
		return
	}
	if reqLen == n {
		// common case, do nothing
	} else if reqLen > n {
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = errReqExtraData
		return
	}

	rawAddress = buf[idAtyp:reqLen]

	switch buf[idAtyp] {
	case typeIPv4:
		address = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		address = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		address = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	address = net.JoinHostPort(address, strconv.Itoa(int(port)))
	return
}

// 第三步
var tryConnectCount = 3
func connectToServer(rawAddress []byte, address string) (remote net.Conn, err error) {
	for i := 0; i < tryConnectCount; i++ {
		remote, err = shine.DialWithRawAddress(rawAddress, serverCipher.Server, serverCipher.Cipher.Copy())
		if err != nil {
			log.Println("error connecting to server:", err)
			continue
		}
		debug.Printf("connected to %s\n", address)
		return
	}
	return nil, errors.New(fmt.Sprintf("still failed to connect to %s after %d attempts", address, tryConnectCount))
}
