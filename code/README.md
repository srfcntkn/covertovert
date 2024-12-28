# Covert Storage Channel that exploits Protocol Field Manipulation using Question - Type field in DNS [Code: CSC-PSV-DNS-QTF]

Covert channels are used to secure information by encoding it in different ways other than transmitting or encoding it directly into the payload. Covert storage channels exploit unused or less-noticed fields in protocols (e.g., IP headers, TCP sequence numbers, or DNS fields) to store and transmit data covertly.


This project implements a covert storage channel that leverages the DNS Question-Type (QTYPE) field for encoding and transmitting hidden messages. The implementation supports encoding 1, 2, or 4 bits per packet.


## Implementation Details

### Encoding and Transmission
The sender encodes binary data into DNS QTYPE fields and transmits the packets using the following strategies:

1. **1 Bit Per Packet:**
   - `QTYPE 1–15`: Encodes binary `0`.
   - `QTYPE 16–30`: Encodes binary `1`.

2. **2 Bits Per Packet:**
   - `QTYPE 1–7`: Encodes `00`.
   - `QTYPE 8–15`: Encodes `01`.
   - `QTYPE 16–23`: Encodes `10`.
   - `QTYPE 24–30`: Encodes `11`.

3. **4 Bits Per Packet:**
   - Encodes binary representations of decimal values using ranges:
     - Special cases:
       - `QTYPE 29`: Encodes `1110` (14).
       - `QTYPE 30`: Encodes `1111` (15).
     - Other values: `QTYPE (2 * decimal + 1)` to `QTYPE (2 * decimal + 2)` for `0–13`.

### Decoding and Reception
The receiver captures DNS packets, extracts the QTYPE field, and decodes the message:
- Aggregates decoded bits into 8-bit segments to reconstruct characters.
- Stops decoding upon detecting the stop character (`.`).



---

## Usage Instructions

### Sender
Configure `config.json` with the following parameters:
   - `log_file_name`: Path to log file for the sent message.
   - `receiver_ip`: IP address of the receiver.
   - `sender_interface`: Network interface for sending packets.
   - `num_bits_per_packet`: Number of bits to encode per packet (1, 2, or 4).

### Receiver
Configure `config.json` with the following parameters:
   - `log_file_name`: Path to log file for the received message.
   - `receiver_interface`: Network interface for capturing packets.
   - `num_bits_per_packet`: Number of bits to decode per packet (1, 2, or 4).

### Important Note
   - Do not write different num_bits_per_packet values for the sender and the reciever paramaters.
---

## Covert Channel Capacity

- When num_bits_per_packet = 4, it took 3.5 seconds to transmit 16 bytes (128/3.5 = 36.6 bits/second)
- When num_bits_per_packet = 2, it took 6 seconds to transmit 16 bytes (128/5.5 = 23.3 bits/second)
- When num_bits_per_packet = 1, it took 11 seconds to transmit 16 bytes (128/10.5 = 12.2 bits/second)

---

## Authors
This implementation was developed as part of the METU CENG 435 Phase 2 programming assignment. It demonstrates the use of protocol field manipulation in covert communication.

- Ertuğrul Kalmaz
- Şerif Can Tekin