package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/gosnmp/gosnmp"
)

func main() {
	// SNMP port
	port := 162

	// Открываем UDP-сокет для прослушивания
	address := fmt.Sprintf(":%d", port)
	conn, err := net.ListenPacket("udp", address)

	if err != nil {
		log.Fatalf("Error creating UDP socket: %v", err)
	}

	defer conn.Close()

	log.Printf("Listen to SNMP on the port %d...\n", port)

	// Opening a file for writing
	file, err := os.OpenFile("snmp_output.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error creating file: %v", err)
	}
	defer file.Close()

	goSnmp := &gosnmp.GoSNMP{
		Port:      uint16(port),
		Transport: "udp",
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(5) * time.Second,
		Retries:   1,
		Logger:    gosnmp.NewLogger(log.Default()),
	}

	buffer := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			log.Printf("Error read: %v", err)
			continue
		}

		// Read Trap
		trapPacket := buffer[:n]
		trap, err := goSnmp.SnmpDecodePacket(trapPacket)
		if err != nil {
			log.Printf("Error decoding SNMP packet: %v", err)
			continue
		}

		// Make json
		trapMessage := map[string]interface{}{
			"from": addr.String(),
			"time": time.Now().Format(time.RFC3339),
			"trap": parseTrap(trap),
		}

		// Prepare trap JSON
		trapJson, err := json.MarshalIndent(trapMessage, "", "  ")
		if err != nil {
			log.Printf("Error Prepare trap JSON: %v", err)
			continue
		}

		if _, err := file.Write(append(trapJson, '\n')); err != nil {
			log.Printf("Error write file: %v", err)
		}

		log.Printf("Received SNMP Trap from %s: %s", addr.String(), string(trapJson))
	}
}

func parseTrap(trap *gosnmp.SnmpPacket) map[string]interface{} {
	data := make(map[string]interface{})
	data["community"] = trap.Community

	vars := []map[string]interface{}{}
	for _, pdu := range trap.Variables {
		vars = append(vars, map[string]interface{}{
			"oid":   pdu.Name,
			"type":  pduTypeToString(pdu.Type),
			"value": parseValue(pdu),
		})
	}

	data["variables"] = vars
	return data
}

func parseValue(pdu gosnmp.SnmpPDU) interface{} {
	switch pdu.Type {
	case gosnmp.OctetString:
		return string(pdu.Value.([]byte))
	default:
		return pdu.Value
	}
}

func pduTypeToString(pduType gosnmp.Asn1BER) string {
	switch pduType {
	case gosnmp.OctetString:
		return "OctetString"
	case gosnmp.Integer:
		return "Integer"
	case gosnmp.ObjectIdentifier:
		return "ObjectIdentifier"
	case gosnmp.TimeTicks:
		return "TimeTicks"
	case gosnmp.Null:
		return "Null"
	case gosnmp.Counter32:
		return "Counter32"
	case gosnmp.Gauge32:
		return "Gauge32"
	case gosnmp.Counter64:
		return "Counter64"
	case gosnmp.IPAddress:
		return "IPAddress"
	default:
		return "Unknown"
	}
}
