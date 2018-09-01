package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/MDGSF/utils"
	"github.com/MDGSF/utils/log"
)

type TConnReq struct {
	Ver      byte
	NMethods byte
	Methods  []byte
}

type TConnRsp struct {
	Ver    byte
	Method byte
}

type TConnDetailReq struct {
	Ver     byte
	Cmd     byte
	Rsv     byte
	Atyp    byte
	DstAddr []byte
	DstPort uint16
}

type TConnDetailRsp struct {
	Ver     byte
	Rep     byte
	Rsv     byte
	Atyp    byte
	BndAddr []byte
	BndPort uint16
}

const (
	Sock5Version = 0x05
	Sock5Rsv     = 0x00
)

const (
	ConnMethodNoAuth            = 0x00
	ConnMethodGSSAPI            = 0x01
	ConnMethodUsernamePassword  = 0x02
	ConnMethodToX7FIANAAssigned = 0x03
	ConnMethodToXFERsv          = 0x80
	ConnMethodNoAcceptMethods   = 0xFF
)

const (
	ConnDetailReqCmdConnect = 0x01
	ConnDetailReqCmdBind    = 0x02
	ConnDetailReqCmdUDP     = 0x03

	ConnDetailReqAtypIPV4       = 0x01
	ConnDetailReqAtypDomainName = 0x03
	ConnDetailReqAtypIPV6       = 0x04
)

const (
	ConnDetailRspRepSucceed                 = 0x00
	ConnDetailRspRepGeneralServerFailure    = 0x01
	ConnDetailRspRepNotAllowedByRuleset     = 0x02
	ConnDetailRspRepNetworkUnreachable      = 0x03
	ConnDetailRspRepHostUnreachable         = 0x04
	ConnDetailRspRepConnRefused             = 0x05
	ConnDetailRspRepTTLExpired              = 0x06
	ConnDetailRspRepCmdNotSupported         = 0x07
	ConnDetailRspRepAddressTypeNotSupported = 0x08
	ConnDetailRspRepToXFFUnassigned         = 0x09

	ConnDetailRspAtypIPV4       = 0x01
	ConnDetailRspAtypDomainName = 0x03
	ConnDetailRspAtypIPV6       = 0x04
)

func readConnReq(conn net.Conn) error {
	//see protocol TConnReq{}
	buf2 := readBytes(conn, 2)
	if buf2[0] != Sock5Version {
		log.Error("[]byte = %v", buf2)
		panic("invalid version number")
	}
	//buf2[0] is version number.
	//buf2[1] is the number of methods.

	// buf3 is methods array, one method is one byte.
	buf3 := readBytes(conn, int(buf2[1]))

	support := false
	for _, method := range buf3 {
		if method == ConnMethodNoAuth {
			support = true
			break
		}
	}
	if !support {
		return errors.New("don't support")
	}

	return nil
}

func readConnDetailReq(conn net.Conn) (*TConnDetailReq, string, error) {
	connDetailReq := &TConnDetailReq{}
	buf4 := readBytes(conn, 4)
	if buf4[0] != Sock5Version {
		log.Error("[]byte = %v", buf4)
		panic("invalid version number")
	}
	if buf4[2] != Sock5Rsv {
		panic("invalid protocol")
	}

	if buf4[1] != ConnDetailReqCmdConnect {
		conn.Write(genConnDetailRsp(ConnDetailRspRepCmdNotSupported))
		return nil, "", errors.New("not support command")
	}

	if buf4[3] != ConnDetailReqAtypIPV4 && buf4[3] != ConnDetailReqAtypDomainName {
		conn.Write(genConnDetailRsp(ConnDetailRspRepAddressTypeNotSupported))
		return nil, "", errors.New("not support address type")
	}

	connDetailReq.Ver = buf4[0]
	connDetailReq.Cmd = buf4[1]
	connDetailReq.Rsv = buf4[2]
	connDetailReq.Atyp = buf4[3]

	var backenAddr string
	if connDetailReq.Atyp == ConnDetailReqAtypIPV4 {

		buf6 := readBytes(conn, 6)
		connDetailReq.DstAddr = make([]byte, 4)
		connDetailReq.DstAddr[0] = buf6[0]
		connDetailReq.DstAddr[1] = buf6[1]
		connDetailReq.DstAddr[2] = buf6[2]
		connDetailReq.DstAddr[3] = buf6[3]
		connDetailReq.DstPort = uint16(buf6[4])*256 + uint16(buf6[5])

		backenAddr = fmt.Sprintf("%d.%d.%d.%d:%d", connDetailReq.DstAddr[0], connDetailReq.DstAddr[1], connDetailReq.DstAddr[2], connDetailReq.DstAddr[3], connDetailReq.DstPort)

	} else if connDetailReq.Atyp == ConnDetailReqAtypDomainName {

		buf1 := readBytes(conn, 1)
		domainNameLen := int(buf1[0])

		bufDomainName := readBytes(conn, domainNameLen)
		connDetailReq.DstAddr = bufDomainName

		buf2 := readBytes(conn, 2)
		connDetailReq.DstPort = uint16(buf2[0])*256 + uint16(buf2[1])

		backenAddr = fmt.Sprintf("%s:%d", bufDomainName, connDetailReq.DstPort)
	}
	return connDetailReq, backenAddr, nil
}

func genConnDetailRsp(rep byte) []byte {
	rsp := &TConnDetailRsp{
		Ver:     Sock5Version,
		Rep:     rep,
		Rsv:     Sock5Rsv,
		Atyp:    0x01,
		BndAddr: []byte{0x00, 0x00, 0x00, 0x00},
		BndPort: 0,
	}
	return []byte{rsp.Ver, rsp.Rep, rsp.Rsv, rsp.Atyp, rsp.BndAddr[0], rsp.BndAddr[1], rsp.BndAddr[2], rsp.BndAddr[3], 0x00, 0x00}
}

func writeConnDetailRspSuccess(conn net.Conn, backenAddr string) {
	rsp := &TConnDetailRsp{
		Ver:     Sock5Version,
		Rep:     ConnDetailRspRepSucceed,
		Rsv:     Sock5Rsv,
		Atyp:    ConnDetailRspAtypIPV4,
		BndAddr: []byte{0x00, 0x00, 0x00, 0x00},
		BndPort: 0,
	}

	pair := strings.Split(backenAddr, ":")
	strip, strport := pair[0], pair[1]

	copy(rsp.BndAddr, net.ParseIP(strip).To4())

	port, err := strconv.Atoi(strport)
	if err != nil {
		panic("invalid port")
	}
	rsp.BndPort = uint16(port)

	conn.Write([]byte{rsp.Ver, rsp.Rep, rsp.Rsv, rsp.Atyp, rsp.BndAddr[0], rsp.BndAddr[1], rsp.BndAddr[2], rsp.BndAddr[3], byte(port / 256), byte(port % 256)})
}

func readBytes(conn io.Reader, count int) []byte {
	buf := make([]byte, count)
	if n, err := io.ReadFull(conn, buf); err != nil || n != count {
		panic(err)
	}
	return buf
}

func iobridge(src io.Reader, dst io.Writer) {
	buf := utils.GLeakyBuf.Get()
	defer utils.GLeakyBuf.Put(buf)
	for {
		n, err := src.Read(buf)
		if err != nil || n == 0 {
			log.Error("read failed, err = %v", err)
			return
		}

		_, err = dst.Write(buf[:n])
		if err != nil {
			log.Error("write failed, err = %v", err)
			return
		}
	}
}

func handleConn(conn net.Conn) {
	log.Info("accept new conn: %v, %v, %v", conn.RemoteAddr().Network(), conn.RemoteAddr().String(), atomic.AddInt32(&connectionNumber, 1))
	defer func() {
		if err := recover(); err != nil {
			log.Error("%v, %v, err = %v", conn.RemoteAddr().Network(), conn.RemoteAddr().String(), err)
		}
		conn.Close()
		log.Info("close conn: %v, %v, %v", conn.RemoteAddr().Network(), conn.RemoteAddr().String(), atomic.AddInt32(&connectionNumber, -1))
	}()

	if err := readConnReq(conn); err != nil {
		//writeConnRspFailed(conn), see protocol TConnRsp{}
		conn.Write([]byte{Sock5Version, ConnMethodNoAcceptMethods})
		return
	}
	//writeConnRspSuccess(conn), see protocol TConnRsp{}
	conn.Write([]byte{Sock5Version, ConnMethodNoAuth})

	_, backenAddr, err := readConnDetailReq(conn)
	if err != nil {
		log.Error("read conn detail request failed, err = %v", err)
		return
	}

	log.Info("net dial backen address = %v", backenAddr)
	backconn, err := net.Dial("tcp", backenAddr)
	if err != nil {
		log.Error("connect to backen addr %v failed, err = %v", backenAddr, err)
		return
	}

	log.Info("connect to backen success: %v, %v", backconn.RemoteAddr().Network(), backconn.RemoteAddr().String())
	defer func() {
		backconn.Close()
		log.Info("close backenconn: %v, %v", backconn.RemoteAddr().Network(), backconn.RemoteAddr().String())
	}()

	writeConnDetailRspSuccess(conn, backconn.RemoteAddr().String())

	go iobridge(conn, backconn)
	iobridge(backconn, conn)
}

var connectionNumber int32

func main() {
	addr := flag.String("addr", ":1080", "localhost:1080")
	flag.Parse()

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Error("listen failed on %v, err = %v", *addr, err)
		return
	}
	log.Info("listen on %v", *addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Error("accept failed, err = %v", err)
			continue
		}
		go handleConn(conn)
	}
}
