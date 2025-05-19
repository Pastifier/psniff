# pSniff: High-Performance Network Packet Sniffer

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Language](https://img.shields.io/badge/Language-C-brightgreen.svg)](https://en.cppreference.com/w/c)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

</div>

## 📖 Overview

pSniff is a high-performance, multi-threaded network packet sniffer and analyzer designed for Linux systems. It leverages the power of libpcap to capture network traffic either from a live interface or from a pre-recorded PCAP file, providing detailed packet analysis and TCP connection tracking.

## ✨ Features

- **Dual Capture Modes**: Analyze live network traffic or parse pre-recorded PCAP files
- **Multi-threaded Architecture**: Separate threads for packet capture, processing, and connection tracking
- **High-performance Connection Tracking**: Efficient hash table implementation for TCP connection state tracking
- **TCP State Machine**: Accurately tracks connection establishment, data transfer, and termination
- **Detailed Packet Analysis**: Extract MAC addresses, IP addresses, port numbers, and more
- **HTTP Traffic Inspection**: Identify GET/POST requests and extract Host and User-Agent information
- **Valgrind Annotations**: Thread-safety verified with Helgrind through custom annotations
- **Resource Management**: Proper cleanup with automatic connection timeouts

## 🛠️ Technical Implementation

- **Thread-safe Queue**: Lock-based queue implementation for passing packet data between threads
- **Adaptive Probing**: Collision handling in the connection table with adaptive probe length
- **Connection Audit**: Dedicated thread for cleaning up stale connections
- **Signal Handling**: Graceful shutdown on program termination signals

## 🚀 Installation

### Prerequisites

- GCC compiler
- libpcap-dev
- pthreads library

```bash
# Install required dependencies on Debian/Ubuntu
sudo apt-get install gcc libpcap-dev
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/Pastifier/psniff.git
cd psniff

# Compile the program
make

# Compile with Valgrind annotations (for threading analysis)
make valgrind

# Clean build artifacts
make clean
```

## 📋 Usage

```bash
# Live capture from network interface
./psniff eth0 live output.log

# Analyze a PCAP file
./psniff capture.pcap file analysis.log
```

### Command Line Arguments

- `interface/pcapfile`: Network interface or path to PCAP file
- `mode`: Either "live" or "file"
- `output_file`: File to write packet information to

## 📊 Performance Considerations

- Uses a custom hash table for O(1) average connection lookup time
- Connection audit thread wakes up only when needed using condition variables
- Reduced lock contention through careful mutex design
- Adaptive probing adjusts based on collision rates

## 📝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔍 Project Structure

```
psniff/
├── Makefile               # Build configuration
├── include/               # Header files
│   ├── psniff.h          # Main header with structures and definitions
│   ├── ps_queue.h        # Thread-safe queue implementation
│   ├── ps_threads.h      # Thread management functions
│   └── ps_valgrind.h     # Valgrind annotations for threading analysis
├── src/                   # Source files
│   ├── main.c            # Entry point and argument handling
│   ├── ps_capture.c      # Packet capture and parsing
│   ├── ps_consumer.c     # Consumer thread for processing packets
│   ├── ps_queue.c        # Queue implementation for thread communication
│   ├── ps_threads.c      # Thread initialization and management
│   └── ps_track.c        # TCP connection tracking logic
└── README.md             # This file
```

## 🧠 My Journey with pSniff

The development of pSniff has been both challenging and rewarding. When I first conceived this project, I aimed to create a simple packet sniffer, but it quickly evolved into a comprehensive networking tool with multiple threads and connection tracking capabilities.

### Challenges Overcome

One of the most significant challenges I faced was implementing proper thread synchronization. Balancing performance with thread safety required careful design decisions, particularly for the connection tracking system where lock contention could significantly impact packet processing speed.

The adaptive probing mechanism for the hash table was another complex aspect. It dynamically adjusts the probe length based on collision rates, which significantly improved performance under heavy loads without sacrificing memory efficiency.

Implementing TCP state tracking also presented interesting challenges. TCP connections don't always follow textbook behaviors in real-world scenarios, especially when dealing with asymmetric routing or packet loss. Creating a robust state machine that gracefully handles these edge cases was quite satisfying.

### Lessons Learned

This project deepened my understanding of:

- Network protocols and packet structures
- Multi-threaded programming and synchronization primitives
- Hash table design and collision resolution strategies
- Performance optimization in real-time processing systems
- System resource management and proper cleanup
