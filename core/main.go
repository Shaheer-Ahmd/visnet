package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/gorilla/websocket"
)

type EventType uint32

const (
	EventTypeProcessExec EventType = 0
	EventTypeProcessExit EventType = 1
	EventTypeConnOpen    EventType = 2
	EventTypeConnClose   EventType = 3
)

type Connection struct {
	Saddr uint32 `json:"saddr"`
	Daddr uint32 `json:"daddr"`
	Sport uint16 `json:"sport"`
	Dport uint16 `json:"dport"`
}

type KernelEvent struct {
	Type EventType
	Pid  uint32
	Ppid uint32
	Comm [16]byte
	Conn Connection
}

type FrontendEvent struct {
	Type EventType  `json:"type"`
	Pid  uint32     `json:"pid"`
	Ppid uint32     `json:"ppid"`
	Comm string     `json:"comm"`
	Conn Connection `json:"conn"`
}

type EventForwarder struct {
	sync.RWMutex
	clients map[*websocket.Conn]bool
}

func NewEventForwarder() *EventForwarder {
	return &EventForwarder{
		clients: make(map[*websocket.Conn]bool),
	}
}

func (ef *EventForwarder) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade WebSocket: %v", err)
		return
	}
	defer conn.Close()

	ef.Lock()
	ef.clients[conn] = true
	ef.Unlock()
	log.Println("Client connected")

	for {
		if _, _, err := conn.NextReader(); err != nil {
			break
		}
	}

	ef.Lock()
	delete(ef.clients, conn)
	ef.Unlock()
	log.Println("Client disconnected")
}

func (ef *EventForwarder) broadcast(event FrontendEvent) {
	ef.RLock()
	defer ef.RUnlock()

	for client := range ef.clients {
		if err := client.WriteJSON(event); err != nil {
			log.Printf("Error broadcasting to client: %v", err)
			client.Close()
			
			ef.RUnlock()
			ef.Lock()
			delete(ef.clients, client)
			ef.Unlock()
			ef.RLock()
		}
	}
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	execTrace, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		log.Fatalf("attaching exec tracepoint: %s", err)
	}
	defer execTrace.Close()

	exitTrace, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	if err != nil {
		log.Fatalf("attaching exit tracepoint: %s", err)
	}
	defer exitTrace.Close()

	tcpV4ConnectEntry, err := link.Kprobe("tcp_v4_connect", objs.TcpV4ConnectEntry, nil)
	if err != nil {
		log.Fatalf("attaching tcp_v4_connect kprobe: %s", err)
	}
	defer tcpV4ConnectEntry.Close()

	tcpV4ConnectExit, err := link.Kretprobe("tcp_v4_connect", objs.TcpV4ConnectExit, nil)
	if err != nil {
		log.Fatalf("attaching tcp_v4_connect kretprobe: %s", err)
	}
	defer tcpV4ConnectExit.Close()

	tcpClose, err := link.Kprobe("tcp_close", objs.TcpClose, nil)
	if err != nil {
		log.Fatalf("attaching tcp_close kprobe: %s", err)
	}
	defer tcpClose.Close()

	inetCskAccept, err := link.Kretprobe("inet_csk_accept", objs.InetCskAcceptRet, nil)
	if err != nil {
		log.Fatalf("attaching inet_csk_accept kretprobe: %s", err)
	}
	defer inetCskAccept.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	log.Println("eBPF probes attached. Forwarding events...")

	forwarder := NewEventForwarder()

	go func() {
		go func() {
			<-stopper
			rd.Close()
		}()

		var kernelEvt KernelEvent
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &kernelEvt); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}
			
			frontendEvt := FrontendEvent{
				Type:   EventType(kernelEvt.Type),
				Pid:    kernelEvt.Pid,
				Ppid:   kernelEvt.Ppid,
				Comm:   string(bytes.TrimRight(kernelEvt.Comm[:], "\x00")),
				Conn:   kernelEvt.Conn,
			}

			forwarder.broadcast(frontendEvt)
		}
	}()

	http.HandleFunc("/ws", forwarder.HandleWebSocket)
	log.Println("WebSocket server listening on :8080")
	go http.ListenAndServe(":8080", nil)

	<-stopper
	log.Println("Exiting...")
}

func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}
