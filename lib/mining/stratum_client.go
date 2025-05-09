package mining

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// StratumClient handles communication with a Bitcoin mining pool using the Stratum protocol
type StratumClient struct {
	conn            net.Conn
	reader          *bufio.Reader
	mutex           sync.Mutex
	poolAddress     string
	poolUser        string
	poolPass        string
	id              atomic.Uint64
	currentJob      *MiningJob
	extraNonce1     string
	extraNonce2Size int
	connected       bool
	connMutex       sync.Mutex
}

// MiningJob represents a Bitcoin mining job received from the pool
type MiningJob struct {
	JobID            string   `json:"job_id"`
	PrevHash         string   `json:"prev_hash"`
	Coinbase1        string   `json:"coinbase1"`
	Coinbase2        string   `json:"coinbase2"`
	MerkleBranches   []string `json:"merkle_branches"`
	Version          string   `json:"version"`
	NBits            string   `json:"nbits"`
	NTime            string   `json:"ntime"`
	CleanJobs        bool     `json:"clean_jobs"`
	PoolDifficulty   float64  `json:"pool_difficulty"`
	ClientDifficulty float64  `json:"client_difficulty"`
}

// ShareSubmission represents a mining share submitted by a client
type ShareSubmission struct {
	JobID       string `json:"job_id"`
	ExtraNonce2 string `json:"extranonce2"`
	NTime       string `json:"ntime"`
	Nonce       string `json:"nonce"`
	Hash        string `json:"hash"`
}

// NewStratumClient creates and initializes a new Stratum client
func NewStratumClient(address, user, pass string) (*StratumClient, error) {
	sc := &StratumClient{
		poolAddress: address,
		poolUser:    user,
		poolPass:    pass,
	}

	err := sc.Connect()
	if err != nil {
		return nil, err
	}

	go sc.Listen()

	return sc, nil
}

// Connect establishes a connection to the mining pool
func (sc *StratumClient) Connect() error {
	sc.connMutex.Lock()
	defer sc.connMutex.Unlock()

	if sc.connected {
		return nil
	}

	// Parse the pool URL to strip protocol
	poolAddress := sc.poolAddress

	// Handle stratum+tcp:// protocol format
	if strings.HasPrefix(poolAddress, "stratum+tcp://") {
		poolAddress = strings.TrimPrefix(poolAddress, "stratum+tcp://")
	}

	log.Printf("Connecting to mining pool at %s", poolAddress)
	conn, err := net.Dial("tcp", poolAddress)
	if err != nil {
		return fmt.Errorf("failed to connect to pool: %w", err)
	}

	sc.conn = conn
	sc.reader = bufio.NewReader(conn)
	sc.connected = true

	// Subscribe to the pool
	err = sc.Subscribe()
	if err != nil {
		conn.Close()
		sc.connected = false
		return fmt.Errorf("subscription failed: %w", err)
	}

	// Authorize with the pool
	err = sc.Authorize()
	if err != nil {
		conn.Close()
		sc.connected = false
		return fmt.Errorf("authorization failed: %w", err)
	}

	log.Printf("Successfully connected to mining pool")
	return nil
}

// Subscribe to mining notifications
func (sc *StratumClient) Subscribe() error {
	id := sc.id.Add(1)
	request := map[string]interface{}{
		"id":     id,
		"method": "mining.subscribe",
		"params": []string{"Anubis/1.0"},
	}

	err := sc.sendRequest(request)
	if err != nil {
		return err
	}

	// Wait for and parse the response
	response, err := sc.reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read subscribe response: %w", err)
	}

	log.Printf("Subscribe response raw: %s", response)

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		return fmt.Errorf("invalid JSON response: %w", err)
	}

	log.Printf("Subscribe result: %v", result)

	// Extract extraNonce1 and extraNonce2Size from response
	if resultArr, ok := result["result"].([]interface{}); ok && len(resultArr) >= 2 {
		log.Printf("Result array: %v", resultArr)
		if subscriptionDetails, ok := resultArr[0].([]interface{}); ok && len(subscriptionDetails) >= 2 {
			// The first item is the subscription ID, which we don't need
			sc.extraNonce1 = resultArr[1].(string)
			sc.extraNonce2Size = int(resultArr[2].(float64))
			log.Printf("Extracted extraNonce1: %s, extraNonce2Size: %d", sc.extraNonce1, sc.extraNonce2Size)
			return nil
		}
	}

	return fmt.Errorf("invalid subscription response format")
}

// Authorize authenticates with the mining pool
func (sc *StratumClient) Authorize() error {
	id := sc.id.Add(1)
	request := map[string]interface{}{
		"id":     id,
		"method": "mining.authorize",
		"params": []string{sc.poolUser, sc.poolPass},
	}

	log.Printf("Sending authorize request with username: %s", sc.poolUser)
	err := sc.sendRequest(request)
	if err != nil {
		log.Printf("Failed to send authorize request: %v", err)
		return err
	}

	// Wait for and parse the response
	response, err := sc.reader.ReadString('\n')
	if err != nil {
		log.Printf("Failed to read authorize response: %v", err)
		return fmt.Errorf("failed to read authorize response: %w", err)
	}

	log.Printf("Authorize response raw: %s", response)

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		log.Printf("Invalid JSON in authorize response: %v", err)
		return fmt.Errorf("invalid JSON response: %w", err)
	}

	log.Printf("Authorize result: %v", result)

	// Check if authorization was successful
	if success, ok := result["result"].(bool); ok && success {
		log.Printf("Authorization successful")
		return nil
	}

	// Check for error details
	if errorObj, ok := result["error"]; ok && errorObj != nil {
		log.Printf("Authorization error: %v", errorObj)
		return fmt.Errorf("authorization failed: %v", errorObj)
	}

	return fmt.Errorf("authorization failed")
}

// Listen continuously reads and processes messages from the pool
func (sc *StratumClient) Listen() {
	for sc.connected {
		line, err := sc.reader.ReadString('\n')
		if err != nil {
			log.Printf("Stratum read error: %v", err)
			sc.Reconnect()
			continue
		}

		// Parse and handle the message
		var message map[string]interface{}
		if err := json.Unmarshal([]byte(line), &message); err != nil {
			log.Printf("Invalid JSON from pool: %v", err)
			continue
		}

		sc.HandleMessage(message)
	}
}

// HandleMessage processes messages received from the mining pool
func (sc *StratumClient) HandleMessage(message map[string]interface{}) {
	// Check for method
	if method, ok := message["method"].(string); ok {
		switch method {
		case "mining.notify":
			// New job notification
			sc.HandleNotify(message)
		case "mining.set_difficulty":
			// Difficulty change
			sc.HandleSetDifficulty(message)
		}
	}

	// Check for result (responses to our requests)
	if _, ok := message["result"]; ok {
		// Handle response
		sc.HandleResponse(message)
	}
}

// HandleNotify processes job notifications from the pool
func (sc *StratumClient) HandleNotify(message map[string]interface{}) {
	params, ok := message["params"].([]interface{})
	if !ok || len(params) < 9 {
		log.Printf("Invalid notify message format")
		return
	}

	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	jobID, _ := params[0].(string)
	prevHash, _ := params[1].(string)
	coinbase1, _ := params[2].(string)
	coinbase2, _ := params[3].(string)
	merkleBranchesRaw, _ := params[4].([]interface{})
	version, _ := params[5].(string)
	nBits, _ := params[6].(string)
	nTime, _ := params[7].(string)
	cleanJobs, _ := params[8].(bool)

	// Convert merkle branches to string array
	merkleBranches := make([]string, len(merkleBranchesRaw))
	for i, branch := range merkleBranchesRaw {
		merkleBranches[i], _ = branch.(string)
	}

	// Get current pool difficulty or use a default value if sc.currentJob is nil
	var poolDifficulty float64 = 10024.0
	if sc.currentJob != nil {
		poolDifficulty = sc.currentJob.PoolDifficulty
	}

	// Update current job
	sc.currentJob = &MiningJob{
		JobID:            jobID,
		PrevHash:         prevHash,
		Coinbase1:        coinbase1,
		Coinbase2:        coinbase2,
		MerkleBranches:   merkleBranches,
		Version:          version,
		NBits:            nBits,
		NTime:            nTime,
		CleanJobs:        cleanJobs,
		PoolDifficulty:   poolDifficulty, // Use the safely obtained difficulty
		ClientDifficulty: 1.0,            // Default client difficulty
	}

	log.Printf("New job received: %s", jobID)
}

// HandleSetDifficulty processes difficulty change notifications
func (sc *StratumClient) HandleSetDifficulty(message map[string]interface{}) {
	params, ok := message["params"].([]interface{})
	if !ok || len(params) < 1 {
		log.Printf("Invalid set_difficulty message format")
		return
	}

	difficulty, ok := params[0].(float64)
	if !ok {
		log.Printf("Invalid difficulty value")
		return
	}

	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if sc.currentJob != nil {
		sc.currentJob.PoolDifficulty = difficulty
		log.Printf("Pool difficulty changed to %f", difficulty)
	}
}

// HandleResponse processes responses to our requests
func (sc *StratumClient) HandleResponse(message map[string]interface{}) {
	// Extract the response ID
	id, ok := message["id"].(float64)
	if !ok {
		log.Printf("Response missing ID")
		return
	}

	log.Printf("Received response for request ID %d", int(id))
}

// GetCurrentJob returns the current mining job
func (sc *StratumClient) GetCurrentJob() *MiningJob {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	if sc.currentJob == nil {
		return nil
	}

	// Return a copy to avoid race conditions
	job := *sc.currentJob
	return &job
}

// GetExtraNonce1 returns the extraNonce1 value
func (sc *StratumClient) GetExtraNonce1() string {
	return sc.extraNonce1
}

// GetExtraNonce2Size returns the extraNonce2Size value
func (sc *StratumClient) GetExtraNonce2Size() int {
	return sc.extraNonce2Size
}

// SubmitShare submits a solution to the pool
func (sc *StratumClient) SubmitShare(jobID, extraNonce2, nTime, nonce string) (bool, error) {
	id := sc.id.Add(1)
	request := map[string]interface{}{
		"id":     id,
		"method": "mining.submit",
		"params": []string{sc.poolUser, jobID, extraNonce2, nTime, nonce},
	}

	err := sc.sendRequest(request)
	if err != nil {
		return false, err
	}

	// In a real implementation, you would need to handle asynchronous responses
	// For simplicity, we'll wait for the immediate response
	response, err := sc.reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read submit response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		return false, fmt.Errorf("invalid JSON response: %w", err)
	}

	// Check if submission was accepted
	if success, ok := result["result"].(bool); ok && success {
		return true, nil
	}

	// If there's an error, extract the error message
	if errorObj, ok := result["error"]; ok && errorObj != nil {
		if errorArr, ok := errorObj.([]interface{}); ok && len(errorArr) > 1 {
			errorMsg, _ := errorArr[1].(string)
			return false, fmt.Errorf("share rejected: %s", errorMsg)
		}
	}

	return false, fmt.Errorf("share rejected")
}

// Reconnect attempts to reconnect to the pool if the connection is lost
func (sc *StratumClient) Reconnect() {
	sc.connMutex.Lock()
	defer sc.connMutex.Unlock()

	if sc.conn != nil {
		sc.conn.Close()
		sc.connected = false
	}

	// Parse the pool URL to strip protocol
	poolAddress := sc.poolAddress

	// Handle stratum+tcp:// protocol format
	if strings.HasPrefix(poolAddress, "stratum+tcp://") {
		poolAddress = strings.TrimPrefix(poolAddress, "stratum+tcp://")
	}

	// Exponential backoff for reconnection attempts
	for i := 0; i < 5; i++ {
		log.Printf("Attempting to reconnect to pool (attempt %d)", i+1)

		conn, err := net.Dial("tcp", poolAddress)
		if err == nil {
			sc.conn = conn
			sc.reader = bufio.NewReader(conn)
			sc.connected = true

			// Re-subscribe and re-authorize
			if err := sc.Subscribe(); err != nil {
				log.Printf("Failed to re-subscribe: %v", err)
				conn.Close()
				continue
			}

			if err := sc.Authorize(); err != nil {
				log.Printf("Failed to re-authorize: %v", err)
				conn.Close()
				continue
			}

			log.Printf("Successfully reconnected to pool")
			return
		}

		log.Printf("Reconnection attempt failed: %v", err)
		time.Sleep(time.Second * time.Duration(1<<i)) // Exponential backoff
	}

	log.Printf("Failed to reconnect to pool after multiple attempts")
}

// sendRequest sends a JSON-RPC request to the mining pool
func (sc *StratumClient) sendRequest(request map[string]interface{}) error {
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("error marshalling request: %w", err)
	}

	// Append newline to the request
	requestJSON = append(requestJSON, '\n')

	_, err = sc.conn.Write(requestJSON)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}

	return nil
}
