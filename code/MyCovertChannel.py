from scapy.all import DNS, DNSQR, IP, UDP, sniff
from CovertChannelBase import CovertChannelBase
import random;

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()

    
    def send(self, log_file_name, receiver_ip, sender_interface, num_bits_per_packet):
        """
        Generate a random binary message, encode it in DNS Question-Type fields,
        and send it to the receiver.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        
        # iterate through the binary message and send each bit
        for i in range(1, int(len(binary_message)/num_bits_per_packet) + 1):

            # read each bit, generate qtype as a random value in a specific range
            # depending on the value of the bit, then set qtype to that value,
            # then send the packet

            if num_bits_per_packet == 1:
                bit = binary_message[i-1]
                qtype = random.randint(1, 15) if bit == "0" else random.randint(16, 30)
                packet = IP(dst=receiver_ip)/UDP(dport=53)/DNS(qd=DNSQR(qtype=qtype))
                super().send(packet, sender_interface)
            
            elif num_bits_per_packet == 2:
                bit1 = binary_message[(i-1)*num_bits_per_packet]
                bit2 = binary_message[(i-1)*num_bits_per_packet + 1]
                if bit1 == "0" and bit2 == "0":
                    qtype = random.randint(1, 7)
                elif bit1 == "0" and bit2 == "1":
                    qtype = random.randint(8, 15)
                elif bit1 == "1" and bit2 == "0":
                    qtype = random.randint(16, 23)
                elif bit1 == "1" and bit2 == "1":
                    qtype = random.randint(24, 30)
                packet = IP(dst=receiver_ip)/UDP(dport=53)/DNS(qd=DNSQR(qtype=qtype))
                super().send(packet, sender_interface)

            elif num_bits_per_packet == 4:
                bit1 = binary_message[(i-1)*num_bits_per_packet]
                bit2 = binary_message[(i-1)*num_bits_per_packet + 1]
                bit3 = binary_message[(i-1)*num_bits_per_packet + 2]
                bit4 = binary_message[(i-1)*num_bits_per_packet + 3]
                binary_value = bit1+bit2+bit3+bit4
                decimal_value = int(binary_value, 2)

                # special cases
                if binary_value == "1110":
                    qtype = 29
                elif binary_value == "1111":
                    qtype = 30
                else:
                    # other cases
                    qtype = random.randint(decimal_value * 2 + 1, decimal_value * 2 + 2)
                packet = IP(dst=receiver_ip)/UDP(dport=53)/DNS(qd=DNSQR(qtype=qtype))
                super().send(packet, sender_interface)


    def receive(self, log_file_name, receiver_interface, num_bits_per_packet):
        """
        Capture DNS packets, decode the Question-Type fields based on num_bits_per_packet to reconstruct the message,
        and log the result. Stop as soon as the stop character is detected.
        """
        def packet_handler(packet):
            # decode the packet
            if packet.haslayer(DNS) and packet[DNS].qd is not None:
                qtype = packet[DNSQR].qtype
                if num_bits_per_packet == 1:
                    return "0" if qtype <= 15 else "1"
                elif num_bits_per_packet == 2:
                    if 1 <= qtype <= 7:
                        return "00"
                    elif 8 <= qtype <= 15:
                        return "01"
                    elif 16 <= qtype <= 23:
                        return "10"
                    elif 24 <= qtype <= 30:
                        return "11"
                elif num_bits_per_packet == 4:
                    if qtype == 29:
                        return "1110"
                    elif qtype == 30:
                        return "1111"
                    else:
                        decimal_value = (qtype - 1) // 2
                        return format(decimal_value, "04b")
            return None

        binary_message = []
        stop_received = False

        def custom_stop_sniffer(packet):
            # handle binary data and detect when to stop
            nonlocal stop_received
            bits = packet_handler(packet)
            if bits:
                binary_message.append(bits)

                reconstructed_binary = "".join(binary_message)
                if len(reconstructed_binary) % 8 == 0:
                    char = self.convert_eight_bits_to_character(reconstructed_binary[-8:])
                    if char == ".":
                        stop_received = True
            return stop_received

        sniff(
            filter="udp port 53",
            iface=receiver_interface,
            prn=custom_stop_sniffer,
            stop_filter=lambda x: stop_received
        )

        reconstructed_binary = "".join(binary_message)
        message = "".join(
            self.convert_eight_bits_to_character(reconstructed_binary[i:i + 8])
            for i in range(0, len(reconstructed_binary), 8)
        )
        self.log_message(message, log_file_name)