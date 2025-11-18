package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// ======================== 全局参数 ========================

var (
	listenAddr    string
	forwardAddr   string
	ipAddr        string
	certFile      string
	keyFile       string
	token         string
	cidrs         string
	connectionNum int

	// 新增 ECH/DNS 参数
	dnsServer string // -dns
	echDomain string // -ech

	// 运行期缓存的 ECHConfigList
	echListMu sync.RWMutex
	echList   []byte

	// 多通道连接池
	echPool *ECHPool
)

func init() {
	flag.StringVar(&listenAddr, "l", "", "监听地址 (tcp://监听1/目标1,监听2/目标2,... 或 ws://ip:port/path 或 wss://ip:port/path 或 socks5://[user:pass@]ip:port)")
	flag.StringVar(&forwardAddr, "f", "", "服务地址 (格式: wss://host:port/path)")
	flag.StringVar(&ipAddr, "ip", "", "指定解析的IP地址（仅客户端：将 wss 主机名定向到该 IP 连接）")
	flag.StringVar(&certFile, "cert", "", "TLS证书文件路径（默认:自动生成，仅服务端）")
	flag.StringVar(&keyFile, "key", "", "TLS密钥文件路径（默认:自动生成，仅服务端）")
	flag.StringVar(&token, "token", "", "身份验证令牌（WebSocket Subprotocol）")
	flag.StringVar(&cidrs, "cidr", "0.0.0.0/0,::/0", "允许的来源 IP 范围 (CIDR),多个范围用逗号分隔")
	flag.StringVar(&dnsServer, "dns", "119.29.29.29:53", "查询 ECH 公钥所用的 DNS 服务器")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "用于查询 ECH 公钥的域名")
	flag.IntVar(&connectionNum, "n", 3, "WebSocket连接数量")
}

func main() {
	flag.Parse()

	if strings.HasPrefix(listenAddr, "ws://") || strings.HasPrefix(listenAddr, "wss://") {
		runWebSocketServer(listenAddr)
		return
	}
	if strings.HasPrefix(listenAddr, "tcp://") {
		// 客户端模式：预先获取 ECH 公钥（失败则直接退出，严格禁止回退）
		if err := prepareECH(); err != nil {
			log.Fatalf("[客户端] 获取 ECH 公钥失败: %v", err)
		}
		runTCPClient(listenAddr, forwardAddr)
		return
	}
	if strings.HasPrefix(listenAddr, "socks5://") {
		// SOCKS5 代理模式：预先获取 ECH 公钥
		if err := prepareECH(); err != nil {
			log.Fatalf("[SOCKS5] 获取 ECH 公钥失败: %v", err)
		}
		runSOCKS5Server(listenAddr, forwardAddr)
		return
	}

	log.Fatal("监听地址格式错误，请使用 ws://, wss://, tcp:// 或 socks5:// 前缀")
}

// 判断是否为正常的网络关闭错误
func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "normal closure")
}

// ======================== ECH 相关（客户端） ========================

const (
	typeHTTPS = 65 // DNS HTTPS 记录类型
)

// 客户端启动时查询 ECH 配置并缓存
func prepareECH() error {
	log.Printf("[客户端] 使用 DNS 服务器查询 ECH: %s -> %s", dnsServer, echDomain)
	echBase64, err := queryHTTPSRecord(echDomain, dnsServer)
	if err != nil {
		return fmt.Errorf("DNS 查询失败: %w", err)
	}
	if echBase64 == "" {
		return errors.New("未找到 ECH 参数（HTTPS RR key=echconfig/5）")
	}
	raw, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return fmt.Errorf("ECH Base64 解码失败: %w", err)
	}
	echListMu.Lock()
	echList = raw
	echListMu.Unlock()
	log.Printf("[客户端] ECHConfigList 长度: %d 字节", len(raw))
	return nil
}

// 刷新 ECH 配置（用于重试）
func refreshECH() error {
	log.Printf("[ECH] 刷新 ECH 公钥配置...")
	return prepareECH()
}

func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 配置尚未加载")
	}
	return echList, nil
}

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("加载系统根证书失败: %w", err)
	}
	tcfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		// 完全采用 ECH，禁止回退
		EncryptedClientHelloConfigList: echList,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			return errors.New("服务器拒绝 ECH（禁止回退）")
		},
		RootCAs: roots,
	}
	return tcfg, nil
}

func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	query := buildDNSQuery(domain, typeHTTPS)

	conn, err := net.Dial("udp", dnsServer)
	if err != nil {
		return "", fmt.Errorf("连接 DNS 服务器失败: %v", err)
	}
	defer conn.Close()

	if _, err = conn.Write(query); err != nil {
		return "", fmt.Errorf("发送查询失败: %v", err)
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return "", fmt.Errorf("读取 DNS 响应失败: %v", err)
	}
	return parseDNSResponse(response[:n])
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	// Header
	query = append(query, 0x00, 0x01)                         // ID
	query = append(query, 0x01, 0x00)                         // 标准查询
	query = append(query, 0x00, 0x01)                         // QDCOUNT = 1
	query = append(query, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // AN/NS/AR = 0
	// QNAME
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00) // root
	// QTYPE/QCLASS
	query = append(query, byte(qtype>>8), byte(qtype))
	query = append(query, 0x00, 0x01) // IN
	return query
}

func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", fmt.Errorf("响应长度无效")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", fmt.Errorf("未找到回答记录")
	}
	// 跳过 Question
	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5 // null + type + class

	// Answers
	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		// NAME（可能压缩）
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8 // type(2) + class(2) + ttl(4)
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)

		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

// 仅抽取 SvcParamKey == 5 (ECHConfigList/echconfig)
func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	// 跳 priority(2)
	offset := 2
	// 跳 targetName
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	// SvcParams
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

// ======================== WebSocket 服务端 ========================

func generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"自签名组织"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

func runWebSocketServer(addr string) {
	u, err := url.Parse(addr)
	if err != nil {
		log.Fatal("无效的 WebSocket 地址:", err)
	}

	path := u.Path
	if path == "" {
		path = "/"
	}

	// 解析多个 CIDR 范围
	var allowedNets []*net.IPNet
	for _, cidr := range strings.Split(cidrs, ",") {
		_, allowedNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			log.Fatalf("无法解析 CIDR: %v", err)
		}
		allowedNets = append(allowedNets, allowedNet)
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
		Subprotocols: func() []string {
			if token == "" {
				return nil
			}
			return []string{token}
		}(),
		ReadBufferSize:  65536, // 增加读缓冲区到64KB
		WriteBufferSize: 65536, // 增加写缓冲区到64KB
	}

	http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		// 验证来源IP
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Printf("无法解析客户端地址: %v", err)
			w.Header().Set("Connection", "close")
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		clientIPAddr := net.ParseIP(clientIP)
		allowed := false
		for _, allowedNet := range allowedNets {
			if allowedNet.Contains(clientIPAddr) {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Printf("拒绝访问: IP %s 不在允许的范围内 (%s)", clientIP, cidrs)
			w.Header().Set("Connection", "close")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// 验证 Subprotocol token
		if token != "" {
			clientToken := r.Header.Get("Sec-WebSocket-Protocol")
			if clientToken != token {
				log.Printf("Token验证失败，来自 %s", r.RemoteAddr)
				w.Header().Set("Connection", "close")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("WebSocket 升级失败:", err)
			return
		}

		log.Printf("新的 WebSocket 连接来自 %s", r.RemoteAddr)
		go handleWebSocket(wsConn)
	})

	// 启动服务器
	if u.Scheme == "wss" {
		server := &http.Server{
			Addr: u.Host,
		}

		if certFile != "" && keyFile != "" {
			log.Printf("WebSocket 服务端使用提供的TLS证书启动，监听 %s%s", u.Host, path)
			server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
			log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
		} else {
			cert, err := generateSelfSignedCert()
			if err != nil {
				log.Fatalf("生成自签名证书时出错: %v", err)
			}
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
			}
			server.TLSConfig = tlsConfig
			log.Printf("WebSocket 服务端使用自签名证书启动，监听 %s%s", u.Host, path)
			log.Fatal(server.ListenAndServeTLS("", ""))
		}
	} else {
		log.Printf("WebSocket 服务端启动，监听 %s%s", u.Host, path)
		log.Fatal(http.ListenAndServe(u.Host, nil))
	}
}

func handleWebSocket(wsConn *websocket.Conn) {
	var mu sync.Mutex
	conns := make(map[string]net.Conn)

	// UDP 连接管理
	udpConns := make(map[string]*net.UDPConn)
	udpTargets := make(map[string]*net.UDPAddr)

	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
		for _, uc := range udpConns {
			_ = uc.Close()
		}
		_ = wsConn.Close()
		log.Printf("WebSocket 连接 %s 已关闭", wsConn.RemoteAddr())
	}()

	// 设置WebSocket保活
	wsConn.SetPingHandler(func(message string) error {
		mu.Lock()
		defer mu.Unlock()
		return wsConn.WriteMessage(websocket.PongMessage, []byte(message))
	})

	for {
		typ, msg, readErr := wsConn.ReadMessage()
		if readErr != nil {
			if !isNormalCloseError(readErr) {
				log.Printf("WebSocket 读取失败 %s: %v", wsConn.RemoteAddr(), readErr)
			}
			return
		}

		if typ == websocket.BinaryMessage {
			// 处理 UDP 数据（带 connID）
			if len(msg) > 9 && string(msg[:9]) == "UDP_DATA:" {
				s := string(msg)
				parts := strings.SplitN(s[9:], "|", 2)
				if len(parts) == 2 {
					connID := parts[0]
					data := []byte(parts[1])

					if udpConn, ok := udpConns[connID]; ok {
						if targetAddr, ok := udpTargets[connID]; ok {
							if _, err := udpConn.WriteToUDP(data, targetAddr); err != nil {
								log.Printf("[服务端UDP:%s] 发送到目标失败: %v", connID, err)
							} else {
								log.Printf("[服务端UDP:%s] 已发送数据到 %s，大小: %d", connID, targetAddr.String(), len(data))
							}
						}
					}
				}
				continue
			}

			// 支持二进制携带文本前缀 "DATA:" 进行多路复用
			if len(msg) > 5 && string(msg[:5]) == "DATA:" {
				s := string(msg)
				parts := strings.SplitN(s[5:], "|", 2)
				if len(parts) == 2 {
					connID := parts[0]
					payload := parts[1]
					if c, ok := conns[connID]; ok {
						if _, err := c.Write([]byte(payload)); err != nil && !isNormalCloseError(err) {
							log.Printf("[服务端] 写入目标失败: %v", err)
							return
						}
					}
				}
				continue
			}
			continue
		}

		data := string(msg)

		// UDP_CONNECT: 建立 UDP 连接（带 connID）
		if strings.HasPrefix(data, "UDP_CONNECT:") {
			parts := strings.SplitN(data[12:], "|", 2)
			if len(parts) == 2 {
				connID := parts[0]
				targetAddr := parts[1]
				log.Printf("[服务端UDP:%s] 收到UDP连接请求，目标: %s", connID, targetAddr)

				udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
				if err != nil {
					log.Printf("[服务端UDP:%s] 解析目标地址失败: %v", connID, err)
					mu.Lock()
					_ = wsConn.WriteMessage(websocket.TextMessage, []byte("UDP_ERROR:"+connID+"|解析地址失败"))
					mu.Unlock()
					continue
				}

				// 为每个 UDP 连接创建独立的套接字
				udpConn, err := net.ListenUDP("udp", nil)
				if err != nil {
					log.Printf("[服务端UDP:%s] 创建UDP套接字失败: %v", connID, err)
					mu.Lock()
					_ = wsConn.WriteMessage(websocket.TextMessage, []byte("UDP_ERROR:"+connID+"|创建UDP失败"))
					mu.Unlock()
					continue
				}

				udpConns[connID] = udpConn
				udpTargets[connID] = udpAddr

				// 启动 UDP 接收 goroutine
				go func(cID string, uc *net.UDPConn) {
					buffer := make([]byte, 65535)
					for {
						n, addr, err := uc.ReadFromUDP(buffer)
						if err != nil {
							if !isNormalCloseError(err) {
								log.Printf("[服务端UDP:%s] 读取失败: %v", cID, err)
							}
							return
						}

						log.Printf("[服务端UDP:%s] 收到响应来自 %s，大小: %d", cID, addr.String(), n)

						// 构建响应消息: UDP_DATA:<connID>|<host>:<port>|<data>
						host, portStr, _ := net.SplitHostPort(addr.String())
						response := []byte(fmt.Sprintf("UDP_DATA:%s|%s:%s|", cID, host, portStr))
						response = append(response, buffer[:n]...)

						mu.Lock()
						_ = wsConn.WriteMessage(websocket.BinaryMessage, response)
						mu.Unlock()
					}
				}(connID, udpConn)

				log.Printf("[服务端UDP:%s] UDP目标已设置: %s", connID, targetAddr)

				// 通知客户端连接成功
				mu.Lock()
				_ = wsConn.WriteMessage(websocket.TextMessage, []byte("UDP_CONNECTED:"+connID))
				mu.Unlock()
			}
			continue
		}

		// UDP_CLOSE: 关闭 UDP 连接
		if strings.HasPrefix(data, "UDP_CLOSE:") {
			connID := strings.TrimPrefix(data, "UDP_CLOSE:")
			if uc, ok := udpConns[connID]; ok {
				_ = uc.Close()
				delete(udpConns, connID)
				delete(udpTargets, connID)
				log.Printf("[服务端UDP:%s] 连接已关闭", connID)
			}
			continue
		}

		// CLAIM: 认领竞选（多通道）
		if strings.HasPrefix(data, "CLAIM:") {
			parts := strings.SplitN(data[6:], "|", 2)
			if len(parts) == 2 {
				connID := parts[0]
				channelID := parts[1]
				mu.Lock()
				_ = wsConn.WriteMessage(websocket.TextMessage, []byte("CLAIM_ACK:"+connID+"|"+channelID))
				mu.Unlock()
			}
			continue
		}

		// TCP: 多路复用建连
		if strings.HasPrefix(data, "TCP:") {
			parts := strings.SplitN(data[4:], "|", 3)
			if len(parts) >= 2 {
				connID := parts[0]
				targetAddr := parts[1]
				var firstFrameData string
				if len(parts) == 3 {
					firstFrameData = parts[2]
				}

				log.Printf("[服务端] 请求TCP转发，连接ID: %s，目标: %s，首帧长度: %d", connID, targetAddr, len(firstFrameData))

				go func(id, target, firstFrame string) {
					tcpConn, err := net.Dial("tcp", target)
					if err != nil {
						log.Printf("[服务端] 连接目标地址 %s 失败: %v", target, err)
						mu.Lock()
						_ = wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE:"+id))
						mu.Unlock()
						return
					}

					// 保存连接
					conns[id] = tcpConn

					// 发送第一帧
					if firstFrame != "" {
						if _, err := tcpConn.Write([]byte(firstFrame)); err != nil {
							log.Printf("[服务端] 发送第一帧失败: %v", err)
							_ = tcpConn.Close()
							delete(conns, id)
							return
						}
					}

					// 通知客户端连接成功
					mu.Lock()
					_ = wsConn.WriteMessage(websocket.TextMessage, []byte("CONNECTED:"+id))
					mu.Unlock()

					// 从目标读取数据并转发
					go func() {
						buf := make([]byte, 4096)
						for {
							n, err := tcpConn.Read(buf)
							if err != nil {
								if !isNormalCloseError(err) {
									log.Printf("[服务端] 从目标读取失败: %v", err)
								}
								mu.Lock()
								_ = wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE:"+id))
								mu.Unlock()
								_ = tcpConn.Close()
								delete(conns, id)
								return
							}
							mu.Lock()
							_ = wsConn.WriteMessage(websocket.BinaryMessage, append([]byte("DATA:"+id+"|"), buf[:n]...))
							mu.Unlock()
						}
					}()
				}(connID, targetAddr, firstFrameData)
			}
			continue
		} else if strings.HasPrefix(data, "DATA:") {
			parts := strings.SplitN(data[5:], "|", 2)
			if len(parts) == 2 {
				id := parts[0]
				payload := parts[1]
				if c, ok := conns[id]; ok {
					if _, err := c.Write([]byte(payload)); err != nil && !isNormalCloseError(err) {
						log.Printf("[服务端] 写入目标失败: %v", err)
						return
					}
				}
			}
			continue
		} else if strings.HasPrefix(data, "CLOSE:") {
			id := strings.TrimPrefix(data, "CLOSE:")
			if c, ok := conns[id]; ok {
				_ = c.Close()
				delete(conns, id)
				log.Printf("[服务端] 客户端请求关闭连接: %s", id)
			}
			continue
		}
	}
}

// ======================== TCP 正向转发客户端（采用 ECH） ========================

func runTCPClient(listenForwardAddr, wsServerAddr string) {
	// 移除 tcp:// 前缀
	rulesStr := strings.TrimPrefix(listenForwardAddr, "tcp://")

	// 按逗号分割多个规则
	rules := strings.Split(rulesStr, ",")

	if len(rules) == 0 {
		log.Fatal("TCP 地址格式错误，应为 tcp://监听地址/目标地址[,监听地址/目标地址...]")
	}

	if wsServerAddr == "" {
		log.Fatal("TCP 正向转发客户端需要指定 WebSocket 服务端地址 (-f)")
	}

	u, err := url.Parse(wsServerAddr)
	if err != nil {
		log.Fatalf("[客户端] 无效的 WebSocket 服务端地址: %v", err)
	}
	if u.Scheme != "wss" {
		log.Fatalf("[客户端] 仅支持 wss://（客户端必须使用 ECH/TLS1.3）")
	}

	echPool = NewECHPool(wsServerAddr, connectionNum)
	echPool.Start()

	var wg sync.WaitGroup

	// 为每个规则启动监听器（多通道模型：启动固定数量的 WebSocket 长连接池）
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		parts := strings.Split(rule, "/")
		if len(parts) != 2 {
			log.Fatalf("规则格式错误: %s，应为 监听地址/目标地址", rule)
		}

		listenAddress := strings.TrimSpace(parts[0])
		targetAddress := strings.TrimSpace(parts[1])

		wg.Add(1)
		go func(listen, target string) {
			defer wg.Done()
			startMultiChannelTCPForwarder(listen, target, echPool)
		}(listenAddress, targetAddress)

		log.Printf("[客户端] 已添加转发规则: %s -> %s", listenAddress, targetAddress)
	}

	log.Printf("[客户端] 共启动 %d 个TCP转发监听器(多通道)", len(rules))

	// 等待所有监听器
	wg.Wait()
}

func startMultiChannelTCPForwarder(listenAddress, targetAddress string, pool *ECHPool) {
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Fatalf("TCP监听失败 %s: %v", listenAddress, err)
	}
	log.Printf("[客户端] TCP正向转发(多通道)监听: %s -> %s", listenAddress, targetAddress)

	// 复用全局池

	// 接受 TCP 连接
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("[客户端] 接受TCP连接失败 %s: %v", listenAddress, err)
			}
			return
		}

		connID := uuid.New().String()
		log.Printf("[客户端] 新的TCP连接 %s，连接ID: %s", tcpConn.RemoteAddr(), connID)

		// 读取第一帧
		_ = tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 32768)
		n, _ := tcpConn.Read(buffer)
		_ = tcpConn.SetReadDeadline(time.Time{})
		first := ""
		if n > 0 {
			first = string(buffer[:n])
		}

		pool.RegisterAndClaim(connID, targetAddress, first, tcpConn)

		if !pool.WaitConnected(connID, 5*time.Second) {
			log.Printf("[客户端] 连接 %s 建立超时，关闭", connID)
			_ = tcpConn.Close()
			continue
		}

		go func(cID string, c net.Conn) {
			buf := make([]byte, 32768)
			for {
				n, err := c.Read(buf)
				if err != nil {
					_ = pool.SendClose(cID)
					_ = c.Close()
					return
				}
				_ = pool.SendData(cID, buf[:n])
			}
		}(connID, tcpConn)
	}
}

// dialWebSocketWithECH 建立 WebSocket 连接（带 ECH 重试）
func dialWebSocketWithECH(wsServerAddr string, maxRetries int) (*websocket.Conn, error) {
	u, err := url.Parse(wsServerAddr)
	if err != nil {
		return nil, fmt.Errorf("解析 wsServerAddr 失败: %v", err)
	}
	serverName := u.Hostname()

	for attempt := 1; attempt <= maxRetries; attempt++ {
		echBytes, echErr := getECHList()
		if echErr != nil {
			log.Printf("[ECH] 获取 ECH 配置失败: %v", echErr)
			if attempt < maxRetries {
				log.Printf("[ECH] 尝试刷新 ECH 配置...")
				if refreshErr := refreshECH(); refreshErr != nil {
					log.Printf("[ECH] 刷新失败: %v", refreshErr)
				}
				continue
			}
			return nil, fmt.Errorf("ECH 配置不可用: %v", echErr)
		}

		tlsCfg, tlsErr := buildTLSConfigWithECH(serverName, echBytes)
		if tlsErr != nil {
			return nil, fmt.Errorf("构建 TLS(ECH) 配置失败: %v", tlsErr)
		}

		// 配置WebSocket Dialer（增加缓冲区大小）
		dialer := websocket.Dialer{
			TLSClientConfig: tlsCfg,
			Subprotocols: func() []string {
				if token == "" {
					return nil
				}
				return []string{token}
			}(),
			HandshakeTimeout: 10 * time.Second,
			ReadBufferSize:   65536, // 增加读缓冲区到64KB
			WriteBufferSize:  65536, // 增加写缓冲区到64KB
		}

		// 如果指定了IP地址，配置自定义拨号器（SNI 仍为 serverName）
		if ipAddr != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				address = net.JoinHostPort(ipAddr, port)
				return net.DialTimeout(network, address, 10*time.Second)
			}
		}

		// 连接到WebSocket服务端（必须 wss）
		wsConn, _, dialErr := dialer.Dial(wsServerAddr, nil)
		if dialErr != nil {
			// 检查是否为 ECH 相关错误
			if strings.Contains(dialErr.Error(), "ECH") || strings.Contains(dialErr.Error(), "ech") {
				log.Printf("[ECH] 连接失败（可能 ECH 公钥已轮换）: %v", dialErr)
				if attempt < maxRetries {
					log.Printf("[ECH] 尝试刷新 ECH 配置并重试 (尝试 %d/%d)...", attempt, maxRetries)
					if refreshErr := refreshECH(); refreshErr != nil {
						log.Printf("[ECH] 刷新失败: %v", refreshErr)
					}
					time.Sleep(time.Second)
					continue
				}
			}
			return nil, dialErr
		}

		return wsConn, nil
	}

	return nil, fmt.Errorf("WebSocket 连接失败，已达最大重试次数")
}

// ======================== SOCKS5 服务器 ========================

// SOCKS5 认证方法常量
const (
	NoAuth       = uint8(0x00)
	UserPassAuth = uint8(0x02)
	NoAcceptable = uint8(0xFF)
)

// SOCKS5 请求命令
const (
	ConnectCmd      = uint8(0x01)
	BindCmd         = uint8(0x02)
	UDPAssociateCmd = uint8(0x03)
)

// SOCKS5 地址类型
const (
	IPv4Addr   = uint8(0x01)
	DomainAddr = uint8(0x03)
	IPv6Addr   = uint8(0x04)
)

// SOCKS5 响应状态码
const (
	Succeeded               = uint8(0x00)
	GeneralFailure          = uint8(0x01)
	ConnectionNotAllowed    = uint8(0x02)
	NetworkUnreachable      = uint8(0x03)
	HostUnreachable         = uint8(0x04)
	ConnectionRefused       = uint8(0x05)
	TTLExpired              = uint8(0x06)
	CommandNotSupported     = uint8(0x07)
	AddressTypeNotSupported = uint8(0x08)
)

type SOCKS5Config struct {
	Username string
	Password string
	Host     string
}

// UDP关联结构（使用连接池）
type UDPAssociation struct {
	connID        string
	tcpConn       net.Conn
	udpListener   *net.UDPConn
	clientUDPAddr *net.UDPAddr
	pool          *ECHPool
	mu            sync.Mutex
	closed        bool
	done          chan bool
	connected     chan bool
	receiving     bool
}

// ======================== 多通道客户端池 ========================

type ECHPool struct {
	wsServerAddr  string
	connectionNum int

	wsConns   []*websocket.Conn
	wsMutexes []sync.Mutex

	mu               sync.RWMutex
	tcpMap           map[string]net.Conn
	udpMap           map[string]*UDPAssociation
	channelMap       map[string]int
	connInfo         map[string]struct{ targetAddr, firstFrameData string }
	claimTimes       map[string]map[int]time.Time
	connected        map[string]chan bool
	boundByChannel   map[int]string
	pendingByChannel map[int]string
}

func NewECHPool(wsServerAddr string, n int) *ECHPool {
	return &ECHPool{
		wsServerAddr:     wsServerAddr,
		connectionNum:    n,
		wsConns:          make([]*websocket.Conn, n),
		wsMutexes:        make([]sync.Mutex, n),
		tcpMap:           make(map[string]net.Conn),
		udpMap:           make(map[string]*UDPAssociation),
		channelMap:       make(map[string]int),
		connInfo:         make(map[string]struct{ targetAddr, firstFrameData string }),
		claimTimes:       make(map[string]map[int]time.Time),
		connected:        make(map[string]chan bool),
		boundByChannel:   make(map[int]string),
		pendingByChannel: make(map[int]string),
	}
}

func (p *ECHPool) Start() {
	for i := 0; i < p.connectionNum; i++ {
		go p.dialOnce(i)
	}
}

func (p *ECHPool) dialOnce(index int) {
	for {
		wsConn, err := dialWebSocketWithECH(p.wsServerAddr, 2)
		if err != nil {
			log.Printf("[客户端] 通道 %d WebSocket(ECH) 连接失败: %v，2秒后重试", index, err)
			time.Sleep(2 * time.Second)
			continue
		}
		p.wsConns[index] = wsConn
		log.Printf("[客户端] 通道 %d WebSocket(ECH) 已连接", index)
		go p.handleChannel(index, wsConn)
		return
	}
}

// RegisterAndClaim 注册一个本地TCP连接，并对所有通道发起认领
func (p *ECHPool) RegisterAndClaim(connID, target, firstFrame string, tcpConn net.Conn) {
	p.mu.Lock()
	p.tcpMap[connID] = tcpConn
	p.connInfo[connID] = struct{ targetAddr, firstFrameData string }{targetAddr: target, firstFrameData: firstFrame}
	if p.claimTimes[connID] == nil {
		p.claimTimes[connID] = make(map[int]time.Time)
	}
	if _, ok := p.connected[connID]; !ok {
		p.connected[connID] = make(chan bool, 1)
	}
	p.mu.Unlock()

	for i, ws := range p.wsConns {
		if ws == nil {
			continue
		}
		p.mu.Lock()
		p.claimTimes[connID][i] = time.Now()
		p.mu.Unlock()
		p.wsMutexes[i].Lock()
		err := ws.WriteMessage(websocket.TextMessage, []byte("CLAIM:"+connID+"|"+fmt.Sprintf("%d", i)))
		p.wsMutexes[i].Unlock()
		if err != nil {
			log.Printf("[客户端] 通道 %d 发送CLAIM失败: %v", i, err)
		}
	}
}

// RegisterUDP 注册UDP关联
func (p *ECHPool) RegisterUDP(connID string, assoc *UDPAssociation) {
	p.mu.Lock()
	p.udpMap[connID] = assoc
	if _, ok := p.connected[connID]; !ok {
		p.connected[connID] = make(chan bool, 1)
	}
	p.mu.Unlock()
}

// SendUDPConnect 发送UDP连接请求（选择第一个可用通道）
func (p *ECHPool) SendUDPConnect(connID, target string) error {
	p.mu.RLock()
	var ws *websocket.Conn
	var chID int
	for i, w := range p.wsConns {
		if w != nil {
			ws = w
			chID = i
			break
		}
	}
	p.mu.RUnlock()

	if ws == nil {
		return fmt.Errorf("没有可用的 WebSocket 连接")
	}

	// 记录通道映射
	p.mu.Lock()
	p.channelMap[connID] = chID
	p.boundByChannel[chID] = connID
	p.mu.Unlock()

	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.TextMessage, []byte("UDP_CONNECT:"+connID+"|"+target))
	p.wsMutexes[chID].Unlock()

	return err
}

// SendUDPData 发送UDP数据
func (p *ECHPool) SendUDPData(connID string, data []byte) error {
	p.mu.RLock()
	chID, ok := p.channelMap[connID]
	var ws *websocket.Conn
	if ok && chID < len(p.wsConns) {
		ws = p.wsConns[chID]
	}
	p.mu.RUnlock()

	if !ok || ws == nil {
		return fmt.Errorf("未分配通道")
	}

	msg := append([]byte("UDP_DATA:"+connID+"|"), data...)
	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.BinaryMessage, msg)
	p.wsMutexes[chID].Unlock()

	return err
}

// SendUDPClose 关闭UDP连接
func (p *ECHPool) SendUDPClose(connID string) error {
	p.mu.RLock()
	chID, ok := p.channelMap[connID]
	var ws *websocket.Conn
	if ok && chID < len(p.wsConns) {
		ws = p.wsConns[chID]
	}
	p.mu.RUnlock()

	if !ok || ws == nil {
		return nil
	}

	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.TextMessage, []byte("UDP_CLOSE:"+connID))
	p.wsMutexes[chID].Unlock()

	// 清理映射
	p.mu.Lock()
	delete(p.channelMap, connID)
	delete(p.boundByChannel, chID)
	delete(p.udpMap, connID)
	p.mu.Unlock()

	return err
}

func (p *ECHPool) WaitConnected(connID string, timeout time.Duration) bool {
	p.mu.RLock()
	ch := p.connected[connID]
	p.mu.RUnlock()
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (p *ECHPool) handleChannel(channelID int, wsConn *websocket.Conn) {
	wsConn.SetPingHandler(func(message string) error {
		p.wsMutexes[channelID].Lock()
		err := wsConn.WriteMessage(websocket.PongMessage, []byte(message))
		p.wsMutexes[channelID].Unlock()
		return err
	})

	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			p.wsMutexes[channelID].Lock()
			_ = wsConn.WriteMessage(websocket.PingMessage, nil)
			p.wsMutexes[channelID].Unlock()
		}
	}()

	for {
		mt, msg, err := wsConn.ReadMessage()
		if err != nil {
			log.Printf("[客户端] 通道 %d WebSocket读取失败: %v", channelID, err)
			// 重连通道
			p.redialChannel(channelID)
			return
		}

		if mt == websocket.BinaryMessage {
			// 处理 UDP 数据响应: UDP_DATA:<connID>|<host>:<port>|<data>
			if len(msg) > 9 && string(msg[:9]) == "UDP_DATA:" {
                parts := bytes.SplitN(msg[9:], []byte("|"), 3)
                if len(parts) == 3 {
                    addrData := string(parts[1])
                    data := parts[2]

					p.mu.RLock()
                    assoc := p.udpMap[string(parts[0])]
					p.mu.RUnlock()

					if assoc != nil {
						assoc.handleUDPResponse(addrData, data)
					}
				}
				continue
			}

			// 支持二进制多路复用：DATA:<id>|<payload>
			if len(msg) > 5 && string(msg[:5]) == "DATA:" {
				s := string(msg)
				parts := strings.SplitN(s[5:], "|", 2)
				if len(parts) == 2 {
					id := parts[0]
					payload := parts[1]
					p.mu.RLock()
					c := p.tcpMap[id]
					p.mu.RUnlock()
					if c != nil {
						_, _ = c.Write([]byte(payload))
					}
					continue
				}
			}
			p.mu.RLock()
			connID := p.boundByChannel[channelID]
			c := p.tcpMap[connID]
			p.mu.RUnlock()
			if connID != "" && c != nil {
				_, _ = c.Write(msg)
			}
			continue
		}

		if mt == websocket.TextMessage {
			data := string(msg)

			// UDP_CONNECTED
			if strings.HasPrefix(data, "UDP_CONNECTED:") {
				connID := strings.TrimPrefix(data, "UDP_CONNECTED:")
				p.mu.RLock()
				ch := p.connected[connID]
				p.mu.RUnlock()
				if ch != nil {
					select {
					case ch <- true:
					default:
					}
				}
				continue
			}

			// UDP_ERROR
			if strings.HasPrefix(data, "UDP_ERROR:") {
				parts := strings.SplitN(data[10:], "|", 2)
				if len(parts) == 2 {
					connID := parts[0]
					errMsg := parts[1]
					log.Printf("[客户端UDP:%s] 错误: %s", connID, errMsg)
				}
				continue
			}

			if strings.HasPrefix(data, "CLAIM_ACK:") {
				parts := strings.SplitN(data[10:], "|", 2)
				if len(parts) == 2 {
					connID := parts[0]
					p.mu.Lock()
					if _, exists := p.channelMap[connID]; exists {
						p.mu.Unlock()
						continue
					}
					info, ok := p.connInfo[connID]
					if !ok {
						p.mu.Unlock()
						continue
					}
					var latency float64
					if chTimes, ok := p.claimTimes[connID]; ok {
						if t, ok := chTimes[channelID]; ok {
							latency = float64(time.Since(t).Nanoseconds()) / 1e6
							delete(chTimes, channelID)
							if len(chTimes) == 0 {
								delete(p.claimTimes, connID)
							}
						}
					}
					p.channelMap[connID] = channelID
					p.boundByChannel[channelID] = connID
					delete(p.connInfo, connID)
					p.mu.Unlock()
					log.Printf("[客户端] 通道 %d 获胜，连接 %s，延迟 %.2fms", channelID, connID, latency)
					p.wsMutexes[channelID].Lock()
					err := wsConn.WriteMessage(websocket.TextMessage, []byte("TCP:"+connID+"|"+info.targetAddr+"|"+info.firstFrameData))
					p.wsMutexes[channelID].Unlock()
					if err != nil {
						p.mu.Lock()
						if c, ok := p.tcpMap[connID]; ok {
							c.Close()
							delete(p.tcpMap, connID)
						}
						delete(p.channelMap, connID)
						delete(p.boundByChannel, channelID)
						delete(p.connInfo, connID)
						delete(p.claimTimes, connID)
						p.mu.Unlock()
						continue
					}
				}
			} else if strings.HasPrefix(data, "CONNECTED:") {
				connID := strings.TrimPrefix(data, "CONNECTED:")
				p.mu.RLock()
				ch := p.connected[connID]
				p.mu.RUnlock()
				if ch != nil {
					select {
					case ch <- true:
					default:
					}
				}
			} else if strings.HasPrefix(data, "ERROR:") {
				log.Printf("[客户端] 通道 %d 错误: %s", channelID, data)
			} else if strings.HasPrefix(data, "CLOSE:") {
				id := strings.TrimPrefix(data, "CLOSE:")
				p.mu.Lock()
				if c, ok := p.tcpMap[id]; ok {
					_ = c.Close()
					delete(p.tcpMap, id)
				}
				delete(p.channelMap, id)
				delete(p.connInfo, id)
				delete(p.claimTimes, id)
				delete(p.boundByChannel, channelID)
				p.mu.Unlock()
			}
		}
	}
}

func (p *ECHPool) redialChannel(channelID int) {
	for {
		newConn, err := dialWebSocketWithECH(p.wsServerAddr, 2)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		p.wsConns[channelID] = newConn
		log.Printf("[客户端] 通道 %d 已重连", channelID)
		go p.handleChannel(channelID, newConn)
		return
	}
}

func (p *ECHPool) SendData(connID string, b []byte) error {
	p.mu.RLock()
	chID, ok := p.channelMap[connID]
	var ws *websocket.Conn
	if ok && chID < len(p.wsConns) {
		ws = p.wsConns[chID]
	}
	p.mu.RUnlock()
	if !ok || ws == nil {
		return fmt.Errorf("未分配通道")
	}
	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.TextMessage, []byte("DATA:"+connID+"|"+string(b)))
	p.wsMutexes[chID].Unlock()
	return err
}

func (p *ECHPool) SendClose(connID string) error {
	p.mu.RLock()
	chID, ok := p.channelMap[connID]
	var ws *websocket.Conn
	if ok && chID < len(p.wsConns) {
		ws = p.wsConns[chID]
	}
	p.mu.RUnlock()
	if !ok || ws == nil {
		return nil
	}
	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.TextMessage, []byte("CLOSE:"+connID))
	p.wsMutexes[chID].Unlock()
	return err
}

func parseSOCKS5Addr(addr string) (*SOCKS5Config, error) {
	// 格式: socks5://[user:pass@]ip:port
	addr = strings.TrimPrefix(addr, "socks5://")

	config := &SOCKS5Config{}

	// 检查是否有认证信息
	if strings.Contains(addr, "@") {
		parts := strings.SplitN(addr, "@", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("无效的 SOCKS5 地址格式")
		}

		// 解析用户名密码
		auth := parts[0]
		if strings.Contains(auth, ":") {
			authParts := strings.SplitN(auth, ":", 2)
			config.Username = authParts[0]
			config.Password = authParts[1]
		}

		config.Host = parts[1]
	} else {
		config.Host = addr
	}

	return config, nil
}

func runSOCKS5Server(addr, wsServerAddr string) {
	if wsServerAddr == "" {
		log.Fatal("SOCKS5 代理需要指定 WebSocket 服务端地址 (-f)")
	}

	// 验证必须使用 wss://（强制 ECH）
	u, err := url.Parse(wsServerAddr)
	if err != nil {
		log.Fatalf("解析 WebSocket 服务端地址失败: %v", err)
	}
	if u.Scheme != "wss" {
		log.Fatalf("[SOCKS5] 仅支持 wss://（客户端必须使用 ECH/TLS1.3）")
	}

	config, err := parseSOCKS5Addr(addr)
	if err != nil {
		log.Fatalf("解析 SOCKS5 地址失败: %v", err)
	}

	listener, err := net.Listen("tcp", config.Host)
	if err != nil {
		log.Fatalf("SOCKS5 监听失败 %s: %v", config.Host, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 服务器启动，监听: %s", config.Host)
	if config.Username != "" {
		log.Printf("SOCKS5 认证已启用，用户名: %s", config.Username)
	}

	echPool = NewECHPool(wsServerAddr, connectionNum)
	echPool.Start()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}

		go handleSOCKS5Connection(conn, config, wsServerAddr)
	}
}

func handleSOCKS5Connection(conn net.Conn, config *SOCKS5Config, wsServerAddr string) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	log.Printf("[SOCKS5:%s] 新连接", clientAddr)

	// 设置连接超时
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 处理认证方法协商
	if err := handleSOCKS5AuthNegotiation(conn, config); err != nil {
		log.Printf("[SOCKS5:%s] 认证方法协商失败: %v", clientAddr, err)
		return
	}

	// 处理用户名密码认证
	if config.Username != "" && config.Password != "" {
		if err := handleSOCKS5UserPassAuth(conn, config); err != nil {
			log.Printf("[SOCKS5:%s] 用户名密码认证失败: %v", clientAddr, err)
			return
		}
	}

	// 处理客户端请求
	if err := handleSOCKS5Request(conn, clientAddr, wsServerAddr, config); err != nil {
		log.Printf("[SOCKS5:%s] 处理请求失败: %v", clientAddr, err)
		return
	}
}

func handleSOCKS5AuthNegotiation(conn net.Conn, config *SOCKS5Config) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取认证方法头失败: %v", err)
	}

	version := buf[0]
	nMethods := buf[1]

	if version != 5 {
		return fmt.Errorf("不支持的SOCKS版本: %d", version)
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("读取认证方法失败: %v", err)
	}

	// 选择认证方法
	var method uint8 = NoAuth
	if config.Username != "" && config.Password != "" {
		method = UserPassAuth
		found := false
		for _, m := range methods {
			if m == UserPassAuth {
				found = true
				break
			}
		}
		if !found {
			method = NoAcceptable
		}
	}

	// 发送选择的认证方法
	response := []byte{0x05, method}
	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("发送认证方法响应失败: %v", err)
	}

	if method == NoAcceptable {
		return fmt.Errorf("没有可接受的认证方法")
	}

	return nil
}

func handleSOCKS5UserPassAuth(conn net.Conn, config *SOCKS5Config) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取用户名密码认证头失败: %v", err)
	}

	version := buf[0]
	userLen := buf[1]

	if version != 1 {
		return fmt.Errorf("不支持的认证版本: %d", version)
	}

	// 读取用户名
	userBuf := make([]byte, userLen)
	if _, err := io.ReadFull(conn, userBuf); err != nil {
		return fmt.Errorf("读取用户名失败: %v", err)
	}

	// 读取密码长度
	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		return fmt.Errorf("读取密码长度失败: %v", err)
	}
	passLen := passLenBuf[0]

	// 读取密码
	passBuf := make([]byte, passLen)
	if _, err := io.ReadFull(conn, passBuf); err != nil {
		return fmt.Errorf("读取密码失败: %v", err)
	}

	// 验证用户名密码
	user := string(userBuf)
	pass := string(passBuf)

	var status byte = 0x00 // 0x00表示成功
	if user != config.Username || pass != config.Password {
		status = 0x01 // 认证失败
	}

	// 发送认证结果
	response := []byte{0x01, status}
	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("发送认证响应失败: %v", err)
	}

	if status != 0x00 {
		return fmt.Errorf("用户名或密码错误")
	}

	return nil
}

func handleSOCKS5Request(conn net.Conn, clientAddr, wsServerAddr string, config *SOCKS5Config) error {
	// 读取请求头
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取请求头失败: %v", err)
	}

	version := buf[0]
	command := buf[1]
	atyp := buf[3]

	if version != 5 {
		return fmt.Errorf("不支持的SOCKS版本: %d", version)
	}

	// 读取目标地址
	var host string
	switch atyp {
	case IPv4Addr:
		buf = make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("读取IPv4地址失败: %v", err)
		}
		host = net.IP(buf).String()

	case DomainAddr:
		buf = make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("读取域名长度失败: %v", err)
		}
		domainLen := buf[0]
		buf = make([]byte, domainLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("读取域名失败: %v", err)
		}
		host = string(buf)

	case IPv6Addr:
		buf = make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("读取IPv6地址失败: %v", err)
		}
		host = net.IP(buf).String()

	default:
		sendSOCKS5ErrorResponse(conn, AddressTypeNotSupported)
		return fmt.Errorf("不支持的地址类型: %d", atyp)
	}

	// 读取端口
	buf = make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取端口失败: %v", err)
	}
	port := int(buf[0])<<8 | int(buf[1])

	// 目标地址
	var target string
	if atyp == IPv6Addr {
		target = fmt.Sprintf("[%s]:%d", host, port)
	} else {
		target = fmt.Sprintf("%s:%d", host, port)
	}

	log.Printf("[SOCKS5:%s] 请求访问目标: %s (命令: %d)", clientAddr, target, command)

	// 处理不同的命令
	switch command {
	case ConnectCmd:
		return handleSOCKS5Connect(conn, target, clientAddr, wsServerAddr)
	case UDPAssociateCmd:
		return handleSOCKS5UDPAssociate(conn, clientAddr, wsServerAddr, config)
	case BindCmd:
		sendSOCKS5ErrorResponse(conn, CommandNotSupported)
		return fmt.Errorf("BIND命令暂不支持")
	default:
		sendSOCKS5ErrorResponse(conn, CommandNotSupported)
		return fmt.Errorf("不支持的命令类型: %d", command)
	}
}

func sendSOCKS5ErrorResponse(conn net.Conn, status uint8) {
	response := []byte{0x05, status, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	conn.Write(response)
}

func sendSOCKS5SuccessResponse(conn net.Conn) error {
	// 简单返回成功响应（绑定地址为 0.0.0.0:0）
	response := []byte{0x05, Succeeded, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(response)
	return err
}

func handleSOCKS5Connect(conn net.Conn, target, clientAddr, wsServerAddr string) error {
	log.Printf("[SOCKS5:%s] 使用连接池建立到 %s 的 CONNECT", clientAddr, wsServerAddr)
	// 复用多通道池，按同样的 CLAIM/ACK 负载策略
	connID := uuid.New().String()
	_ = conn.SetDeadline(time.Time{})
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buffer := make([]byte, 32768)
	n, _ := conn.Read(buffer)
	_ = conn.SetReadDeadline(time.Time{})
	first := ""
	if n > 0 {
		first = string(buffer[:n])
	}

	echPool.RegisterAndClaim(connID, target, first, conn)
	if !echPool.WaitConnected(connID, 5*time.Second) {
		sendSOCKS5ErrorResponse(conn, GeneralFailure)
		return fmt.Errorf("SOCKS5 CONNECT 超时")
	}
	if err := sendSOCKS5SuccessResponse(conn); err != nil {
		return fmt.Errorf("发送SOCKS5成功响应失败: %v", err)
	}

	// 数据转发由池的通道处理（WS->TCP 在池里），这里只需阻塞直到连接关闭
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				close(done)
				return
			}
			_ = echPool.SendData(connID, buf[:n])
		}
	}()
	<-done
	return nil
}

// ======================== SOCKS5 UDP ASSOCIATE（使用连接池） ========================

// handleSOCKS5UDPAssociate 处理UDP ASSOCIATE请求（使用ECH连接池）
func handleSOCKS5UDPAssociate(tcpConn net.Conn, clientAddr, wsServerAddr string, config *SOCKS5Config) error {
    _ = wsServerAddr
	log.Printf("[SOCKS5:%s] 处理UDP ASSOCIATE请求（使用连接池）", clientAddr)

	// 获取SOCKS5服务器的监听IP（根据配置）
	host, _, err := net.SplitHostPort(config.Host)
	if err != nil {
		sendSOCKS5ErrorResponse(tcpConn, GeneralFailure)
		return fmt.Errorf("解析监听地址失败: %v", err)
	}

	// 创建UDP监听器（端口由系统自动分配，IP使用配置的监听IP）
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		sendSOCKS5ErrorResponse(tcpConn, GeneralFailure)
		return fmt.Errorf("解析UDP地址失败: %v", err)
	}

	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		sendSOCKS5ErrorResponse(tcpConn, GeneralFailure)
		return fmt.Errorf("UDP监听失败: %v", err)
	}
	defer udpListener.Close()

	// 获取实际监听的端口
	actualAddr := udpListener.LocalAddr().(*net.UDPAddr)
	log.Printf("[SOCKS5:%s] UDP中继服务器启动: %s（通过连接池）", clientAddr, actualAddr.String())

	// 发送成功响应（包含UDP中继服务器的地址和端口）
	err = sendSOCKS5UDPResponse(tcpConn, actualAddr)
	if err != nil {
		return fmt.Errorf("发送UDP响应失败: %v", err)
	}

	// 生成连接ID并创建UDP关联
	connID := uuid.New().String()
	assoc := &UDPAssociation{
		connID:      connID,
		tcpConn:     tcpConn,
		udpListener: udpListener,
		pool:        echPool,
		done:        make(chan bool, 2),
		connected:   make(chan bool, 1),
	}

	// 注册到连接池
	echPool.RegisterUDP(connID, assoc)

	log.Printf("[SOCKS5:%s] UDP关联已创建，连接ID: %s", clientAddr, connID)

	// 清除TCP连接超时（保持连接活跃）
	tcpConn.SetDeadline(time.Time{})

	// 启动UDP数据处理goroutine
	go assoc.handleUDPRelay()

	// 监听TCP控制连接（阻塞等待）
	go func() {
		buf := make([]byte, 1)
		for {
			_, err := tcpConn.Read(buf)
			if err != nil {
				log.Printf("[SOCKS5:%s] TCP控制连接断开，终止UDP关联", clientAddr)
				assoc.done <- true
				return
			}
		}
	}()

	// 等待结束信号（TCP断开或UDP出错）
	<-assoc.done

	assoc.Close()
	log.Printf("[SOCKS5:%s] UDP关联已终止，连接ID: %s", clientAddr, connID)

	return nil
}

// sendSOCKS5UDPResponse 发送UDP ASSOCIATE成功响应
func sendSOCKS5UDPResponse(conn net.Conn, udpAddr *net.UDPAddr) error {
	response := make([]byte, 0, 22)
	response = append(response, 0x05, Succeeded, 0x00)

	// 地址类型和地址
	ip := udpAddr.IP
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		response = append(response, IPv4Addr)
		response = append(response, ip4...)
	} else {
		// IPv6
		response = append(response, IPv6Addr)
		response = append(response, ip...)
	}

	// 端口
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(udpAddr.Port))
	response = append(response, port...)

	_, err := conn.Write(response)
	return err
}

// handleUDPRelay 处理UDP数据中继（使用连接池）
func (assoc *UDPAssociation) handleUDPRelay() {
	buffer := make([]byte, 65535)

	for {
		n, srcAddr, err := assoc.udpListener.ReadFromUDP(buffer)
		if err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[UDP:%s] 读取失败: %v", assoc.connID, err)
			}
			assoc.done <- true
			return
		}

		// 第一次收到UDP包时，记录客户端UDP地址
		if assoc.clientUDPAddr == nil {
			assoc.mu.Lock()
			if assoc.clientUDPAddr == nil {
				assoc.clientUDPAddr = srcAddr
				log.Printf("[UDP:%s] 客户端UDP地址: %s", assoc.connID, srcAddr.String())
			}
			assoc.mu.Unlock()
		} else {
			// 验证UDP包来自正确的客户端
			if assoc.clientUDPAddr.String() != srcAddr.String() {
				log.Printf("[UDP:%s] 忽略来自未授权地址的UDP包: %s", assoc.connID, srcAddr.String())
				continue
			}
		}

		log.Printf("[UDP:%s] 收到UDP数据包，大小: %d", assoc.connID, n)

		// 处理UDP数据包
		go assoc.handleUDPPacket(buffer[:n])
	}
}

// handleUDPPacket 处理单个UDP数据包（通过连接池）
func (assoc *UDPAssociation) handleUDPPacket(packet []byte) {
	// 解析SOCKS5 UDP请求头
	target, data, err := parseSOCKS5UDPPacket(packet)
	if err != nil {
		log.Printf("[UDP:%s] 解析UDP数据包失败: %v", assoc.connID, err)
		return
	}

	log.Printf("[UDP:%s] 目标: %s, 数据长度: %d", assoc.connID, target, len(data))

	// 通过连接池发送数据
	if err := assoc.sendUDPData(target, data); err != nil {
		log.Printf("[UDP:%s] 发送数据失败: %v", assoc.connID, err)
		return
	}
}

// sendUDPData 通过连接池发送UDP数据
func (assoc *UDPAssociation) sendUDPData(target string, data []byte) error {
	assoc.mu.Lock()
	defer assoc.mu.Unlock()

	if assoc.closed {
		return fmt.Errorf("关联已关闭")
	}

	// 只在第一次发送时建立连接
	if !assoc.receiving {
		assoc.receiving = true
		// 发送UDP_CONNECT消息（包含目标地址）
		if err := assoc.pool.SendUDPConnect(assoc.connID, target); err != nil {
			return fmt.Errorf("发送UDP_CONNECT失败: %v", err)
		}

		// 等待连接成功
		go func() {
			if !assoc.pool.WaitConnected(assoc.connID, 5*time.Second) {
				log.Printf("[UDP:%s] 连接超时", assoc.connID)
				assoc.done <- true
				return
			}
			log.Printf("[UDP:%s] 连接已建立", assoc.connID)
		}()
	}

	// 发送实际数据
	if err := assoc.pool.SendUDPData(assoc.connID, data); err != nil {
		return fmt.Errorf("发送UDP数据失败: %v", err)
	}

	return nil
}

// handleUDPResponse 处理从WebSocket返回的UDP数据
func (assoc *UDPAssociation) handleUDPResponse(addrData string, data []byte) {
	// 解析地址 "host:port"
	parts := strings.Split(addrData, ":")
	if len(parts) != 2 {
		log.Printf("[UDP:%s] 无效的地址格式: %s", assoc.connID, addrData)
		return
	}

	host := parts[0]
	port := 0
	fmt.Sscanf(parts[1], "%d", &port)

	// 构建SOCKS5 UDP响应包
	packet, err := buildSOCKS5UDPPacket(host, port, data)
	if err != nil {
		log.Printf("[UDP:%s] 构建响应包失败: %v", assoc.connID, err)
		return
	}

	// 发送回客户端
	if assoc.clientUDPAddr != nil {
		assoc.mu.Lock()
		_, err = assoc.udpListener.WriteToUDP(packet, assoc.clientUDPAddr)
		assoc.mu.Unlock()

		if err != nil {
			log.Printf("[UDP:%s] 发送UDP响应失败: %v", assoc.connID, err)
			assoc.done <- true
			return
		}

		log.Printf("[UDP:%s] 已发送UDP响应: %s:%d, 大小: %d", assoc.connID, host, port, len(data))
	}
}

func (assoc *UDPAssociation) IsClosed() bool {
	assoc.mu.Lock()
	defer assoc.mu.Unlock()
	return assoc.closed
}

func (assoc *UDPAssociation) Close() {
	assoc.mu.Lock()
	defer assoc.mu.Unlock()

	if assoc.closed {
		return
	}

	assoc.closed = true

	// 通过连接池关闭UDP连接
	if assoc.pool != nil {
		assoc.pool.SendUDPClose(assoc.connID)
	}

	if assoc.udpListener != nil {
		assoc.udpListener.Close()
	}

	log.Printf("[UDP:%s] 关联资源已清理", assoc.connID)
}

// parseSOCKS5UDPPacket 解析SOCKS5 UDP数据包
func parseSOCKS5UDPPacket(packet []byte) (string, []byte, error) {
	if len(packet) < 10 {
		return "", nil, fmt.Errorf("数据包太短")
	}

	// RSV (2字节) + FRAG (1字节)
	if packet[0] != 0 || packet[1] != 0 {
		return "", nil, fmt.Errorf("无效的RSV字段")
	}

	frag := packet[2]
	if frag != 0 {
		return "", nil, fmt.Errorf("不支持分片 (FRAG=%d)", frag)
	}

	atyp := packet[3]
	offset := 4

	var host string
	switch atyp {
	case IPv4Addr:
		if len(packet) < offset+4 {
			return "", nil, fmt.Errorf("IPv4地址不完整")
		}
		host = net.IP(packet[offset : offset+4]).String()
		offset += 4

	case DomainAddr:
		if len(packet) < offset+1 {
			return "", nil, fmt.Errorf("域名长度字段缺失")
		}
		domainLen := int(packet[offset])
		offset++
		if len(packet) < offset+domainLen {
			return "", nil, fmt.Errorf("域名数据不完整")
		}
		host = string(packet[offset : offset+domainLen])
		offset += domainLen

	case IPv6Addr:
		if len(packet) < offset+16 {
			return "", nil, fmt.Errorf("IPv6地址不完整")
		}
		host = net.IP(packet[offset : offset+16]).String()
		offset += 16

	default:
		return "", nil, fmt.Errorf("不支持的地址类型: %d", atyp)
	}

	// 端口
	if len(packet) < offset+2 {
		return "", nil, fmt.Errorf("端口字段缺失")
	}
	port := int(packet[offset])<<8 | int(packet[offset+1])
	offset += 2

	// 实际数据
	data := packet[offset:]

	var target string
	if atyp == IPv6Addr {
		target = fmt.Sprintf("[%s]:%d", host, port)
	} else {
		target = fmt.Sprintf("%s:%d", host, port)
	}

	return target, data, nil
}

// buildSOCKS5UDPPacket 构建SOCKS5 UDP响应数据包
func buildSOCKS5UDPPacket(host string, port int, data []byte) ([]byte, error) {
	packet := make([]byte, 0, 1024)

	// RSV (2字节) + FRAG (1字节)
	packet = append(packet, 0x00, 0x00, 0x00)

	// 解析地址类型
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4
			packet = append(packet, IPv4Addr)
			packet = append(packet, ip4...)
		} else {
			// IPv6
			packet = append(packet, IPv6Addr)
			packet = append(packet, ip...)
		}
	} else {
		// 域名
		if len(host) > 255 {
			return nil, fmt.Errorf("域名过长")
		}
		packet = append(packet, DomainAddr)
		packet = append(packet, byte(len(host)))
		packet = append(packet, []byte(host)...)
	}

	// 端口
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	packet = append(packet, portBytes...)

	// 数据
	packet = append(packet, data...)

	return packet, nil
}
