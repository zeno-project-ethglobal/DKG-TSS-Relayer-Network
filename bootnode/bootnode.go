package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

type Message struct {
	Command string      `json:"command"`
	Data    interface{} `json:"data"`
}

type NodeInfo struct {
	ID   string `json:"id"`
	Addr string `json:"addr"`
}

// bootnode storage file name
const peersFile = "./data/peers.json"

// Load peers from file
func loadPeers() map[string]string {
	data, err := os.ReadFile(peersFile)
	if err != nil {
		// If file doesn't exist, return empty map
		return make(map[string]string)
	}

	var peers map[string]string
	if err := json.Unmarshal(data, &peers); err != nil {
		log.Println("Error parsing peers.json:", err)
		return make(map[string]string)
	}

	return peers
}

// Save peers to file
func savePeers(peers map[string]string) {
	data, _ := json.MarshalIndent(peers, "", "  ")
	_ = os.WriteFile(peersFile, data, 0644)
}

// handleConnection processes incoming messages from a peer
func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Get client address for logging
	clientAddr := conn.RemoteAddr().String()
	fmt.Printf("📞 New connection from %s\n", clientAddr)

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	// FIX: Handle EOF error properly and don't use infinite loop for single request-response
	for {
		var msg Message
		if err := decoder.Decode(&msg); err != nil {
			if err == io.EOF {
				fmt.Printf("📴 Client %s disconnected (EOF)\n", clientAddr)
				return
			}
			fmt.Printf("❌ Error decoding from %s: %v\n", clientAddr, err)
			return
		}

		fmt.Printf("📨 Received command '%s' from %s\n", msg.Command, clientAddr)

		var response interface{}
		shouldClose := false

		// Switch based on the command
		switch msg.Command {
		case "REGISTER":
			response, shouldClose = handleRegister(msg, clientAddr)
		default:
			fmt.Printf("❓ Unknown command from %s: %s\n", clientAddr, msg.Command)
			response = Message{
				Command: "ERROR",
				Data:    "unknown command",
			}
			shouldClose = true
		}

		// Send response
		if err := encoder.Encode(response); err != nil {
			fmt.Printf("❌ Error sending response to %s: %v\n", clientAddr, err)
			return
		}

		// FIX: Close connection after single request-response cycle for REGISTER
		if shouldClose {
			fmt.Printf("✅ Completed request from %s, closing connection\n", clientAddr)
			return
		}
	}
}

// handleRegister processes REGISTER command
func handleRegister(msg Message, clientAddr string) (interface{}, bool) {
	var node NodeInfo
	b, _ := json.Marshal(msg.Data)
	_ = json.Unmarshal(b, &node)

	fmt.Printf("🔗 Node registered: ID=%s, Addr=%s (from %s)\n",
		node.ID, node.Addr, clientAddr)

	// Load existing peers
	peers := loadPeers()
	updated := false

	// Check if address exists with a different ID
	for existingID, existingAddr := range peers {
		if existingAddr == node.Addr && existingID != node.ID {
			// Update ID for this address
			delete(peers, existingID)
			peers[node.ID] = node.Addr
			updated = true
			fmt.Printf("🔄 Updated existing address %s: %s -> %s\n",
				node.Addr, existingID, node.ID)
			break
		}
	}

	// Check if ID exists with a different address
	if !updated {
		if existingAddr, ok := peers[node.ID]; ok && existingAddr != node.Addr {
			// Update address for this ID
			peers[node.ID] = node.Addr
			updated = true
			fmt.Printf("🔄 Updated address for %s: %s -> %s\n",
				node.ID, existingAddr, node.Addr)
		}
	}

	// If neither existed, add normally
	if !updated {
		peers[node.ID] = node.Addr
		fmt.Printf("➕ Added new peer: %s -> %s\n", node.ID, node.Addr)
	}

	// Save peers
	savePeers(peers)
	fmt.Printf("💾 Saved %d peers to %s\n", len(peers), peersFile)

	// Send back confirmation with peer list
	response := Message{
		Command: "PEERLIST",
		Data:    peers,
	}

	fmt.Printf("📤 Sending peerlist with %d peers to %s\n", len(peers), clientAddr)

	// Return response and indicate connection should close
	return response, true
}

// startServer listens for new connections
func startServer(port string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}

	defer ln.Close()
	fmt.Printf("🚀 Bootnode listening on port %s\n", port)
	fmt.Printf("📁 Using peers file: %s\n", peersFile)

	// Load and display existing peers
	peers := loadPeers()
	fmt.Printf("📊 Loaded %d existing peers\n", len(peers))

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("❌ Accept error:", err)
			continue
		}

		// Handle each connection in a separate goroutine
		go handleConnection(conn)
	}
}

// ---------- Cleanup on exit ----------
func cleanupOnExit() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Printf("🧹 Cleaning up %s...\n", peersFile)
		os.Remove(peersFile)
		os.Exit(0)
	}()
}

func main() {
	fmt.Println("🔗 Starting DKG Bootnode...")
	cleanupOnExit()
	startServer("9000")
}
