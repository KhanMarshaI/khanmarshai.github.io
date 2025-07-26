---
title: "Watch Tower"
date: 2025-07-26 16:05:00 +0500
categories: [Challenges]
tags: [HTB, Very Easy, ICS, PCAP File, Modbus Protocol]
---

## PCAP File

The packet capture is of Modbus/TCP. 

### Modbus

Modbus is a communication protocol developed in 1979 by Modicon (now Schneider Electric) for industrial automation systems. It enables data exchange between electronic devices like PLCs (Programmable Logic Controllers), sensors, HMIs (Human-Machine Interfaces), and other industrial equipment.

- Master/Slave (Client/Server) Architecture: One master (client) controls communication with multiple slaves (servers).
- Function Codes: Define operations like read/write coils (digital I/O), registers (analog data), diagnostics, etc.

Common Use Cases
- Factory automation (robotics, conveyors).
- Energy management (smart meters, solar inverters).
- Building automation (HVAC, lighting systems).
- Water treatment plants.

### Modbus/TCP

Modbus/TCP is the Ethernet-based version of the Modbus protocol. It takes the same simple Modbus frame format and wraps it inside standard TCP/IP packets instead of sending it over a serial line. That single change gives Modbus the speed, distance, and flexibility of modern Ethernet networks while keeping the familiar register/coil data model and function codes.

---

One thing I noticed on each packet was a Unit number and a Function number. What do they mean?

### Unit and Function Numbers

| Numbers              | In Modbus terminology                | What it actually does                                                                                                                                |
| --------------------------- | ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Unit = 1, Function = 1**  | **Read Coils (FC=01)**               | The master/client asks **slave/server with address 1** to return the **ON/OFF state** of one or more **coils** (digital outputs or internal relays). |
| **Unit = 1, Function = 15** | **Write Multiple Coils (FC=15)**     | The master tells **slave 1** to **turn ON or OFF** a consecutive block of coils in a single message.                                                 |
| **Unit = 1, Function = 16** | **Write Multiple Registers (FC=16)** | The master writes one or more **16-bit holding registers** (analog outputs, set-points, configuration words, etc.) to **slave 1**.                   |

1. Read Coils (FC=01) – read bits (0/1) starting at a given address.
2. Write Multiple Registers (FC=16) – write 16-bit words starting at a given address.

---

## Flag

We follow the TCP stream and from Packet 129 we can start reading the flag HTB{xxx}, word by word.

