package main

import (
	"flag"
	"shine/shine"
	"os"
	"log"
	"errors"
	"net"
	"strconv"
	"io"
	"fmt"
	"encoding/binary"
	"strings"
	"syscall"
)

var debug shine.DebugLog
var config *shine.Config

const (
	idType  = 0 // address type index
	idIP0   = 1 // ip addres start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	lenPort = 2
	lenIPv4 = net.IPv4len + lenPort // ipv4 + 2port
	lenIPv6 = net.IPv6len + lenPort // ipv6 + 2port

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
	config, err = shine.ParseConfig(configFile)
	if err != nil {
		log.Fatal("parse config err: ", err)
	}
	if !enoughOptions(config) {
		log.Fatal("missing some config field")
	}

	if err = shine.CheckCipherMethod(config.Method); err != nil {
		log.Fatal(err)
	}
	run(config)
}

func enoughOptions(config *shine.Config) bool {
	return config.ServerPort != 0 && config.Password != ""
}

type PortListener struct {
	password string
	listener net.Listener
}

func run(config *shine.Config) {
	port := config.ServerPort
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		log.Fatalf("error listening port %d: %v\n", port, err)
	}
	log.Printf("server listening port %d ...\n", port)
	var cipher *shine.Cipher
	for {
		conn, err := ln.Accept()
		if err != nil {
			debug.Printf("accept error: %v\n", err)
			return
		}
		if cipher == nil {
			cipher, err = shine.NewCipher(config.Method, config.Password)
			if err != nil {
				log.Printf("Error generating cipher for port: %d %v\n", port, err)
				conn.Close()
				continue
			}

		}
		go handleConnection(shine.NewConn(conn, cipher.Copy()))
	}

}

func handleConnection(conn *shine.Conn) {
	var address string
	debug.Printf("new client %s -> %s\n", conn.RemoteAddr().String(), conn.LocalAddr().String())
	closed := false
	defer func() {
		debug.Printf("closed pipe %s<->%s\n", conn.RemoteAddr(), address)
		if !closed {
			conn.Close()
		}
	}()
	address, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request", conn.RemoteAddr(), conn.LocalAddr(), err)
		closed = true
		return
	}
	// ensure the host does not contain some illegal characters, NUL may panic on Win32
	if strings.ContainsRune(address, 0x00) {
		log.Println("invalid domain name.")
		closed = true
		return
	}
	debug.Println("connecting to", address)
	remote, err := net.Dial("tcp", address)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			log.Println("dial error:", err)
		} else {
			log.Println("error connecting to:", remote, err)
		}
		return
	}
	defer func() {
		if !closed {
			remote.Close()
		}
	}()
	debug.Printf("piping %s<->%s", conn.RemoteAddr(), address)
	go shine.PipeThenClose(conn, remote)
	shine.PipeThenClose(remote, conn)
	closed = true
	return
}

func getRequest(conn *shine.Conn) (address string, err error) {
	shine.SetReadTimeout(conn)

	// client写入过来的是: rawAddress (idType + IP/Domain) + iv
	// 16  1(addrType) + 1(lenByte) + 255(max length address) + 2(port)
	buf := make([]byte, 259)

	// ReadFull会调用到conn.Read
	// shine.Conn重写了Read方法
	if _, err = io.ReadFull(conn, buf[:idType+1]); err != nil {
		return
	}
	var reqStart, reqEnd int
	addressType := buf[idType]
	switch addressType {
	case typeIPv4:
		reqStart, reqEnd = idIP0, idIP0+lenIPv4
	case typeIPv6:
		reqStart, reqEnd = idIP0, idIP0+lenIPv6
	case typeDm:
		if _, err = io.ReadFull(conn, buf[idType+1:idDmLen+1]); err != nil {
			return
		}
		reqStart, reqEnd = idDm0, idDm0+int(buf[idDmLen])+lenPort
	default:
		err = fmt.Errorf("addr type %d not supported", addressType)
		return
	}
	if _, err = io.ReadFull(conn, buf[reqStart:reqEnd]); err != nil {
		return
	}
	switch addressType {
	case typeIPv4:
		address = net.IP(buf[idIP0: idIP0+net.IPv4len]).String()
	case typeIPv6:
		address = net.IP(buf[idIP0: idIP0+net.IPv6len]).String()
	case typeDm:
		address = string(buf[idDm0: idDm0+int(buf[idDmLen])])
	}

	port := binary.BigEndian.Uint16(buf[reqEnd-2: reqEnd])
	address = net.JoinHostPort(address, strconv.Itoa(int(port)))
	return
}
