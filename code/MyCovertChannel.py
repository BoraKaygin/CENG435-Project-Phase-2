#import string
from CovertChannelBase import CovertChannelBase
from scapy.all import IP, TCP, sniff
#from decimal import Decimal
import time

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass
    def send(self, source_ip, destination_ip, destination_port, xor_code, log_file_name):
        """
        - Each bit is XORed with the corresponding bit of the xor_code in line 29
        - This is done explicitly with an if statement
        - The packet is sent with the URG flag set if the XOR encoded bit is 1, and not set if the bit is 0
        - The commented out code is for testing and benchmarking purposes
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        #binary_message = self.generate_random_binary_message_with_logging(log_file_name, 16, 16)
        #binary_message = self.generate_random_binary_message_with_logging(log_file_name, 100, 100)
        binary_code = self.convert_string_message_to_binary(xor_code)
        code_index = 0
        
        #start = time.time()
        for bit in binary_message:
            encoded_bit = "1" if bit == "1" and binary_code[code_index] == "0" or bit == "0" and binary_code[code_index] == "1" else "0"
            packet = IP(src=source_ip, dst=destination_ip) / TCP(flags="U" if encoded_bit == "1" else "", dport=destination_port)
            CovertChannelBase.send(self, packet)
            code_index += 1
        #end = time.time()
        #bps = len(binary_message) / (end - start)
        #print("Sent {} bits in {} seconds. {} bits per second.".format(len(binary_message), end - start, bps))
        
    def receive(self, filter, xor_code, log_file_name):
        """
        - The packet is received and the URG flag is checked
        - If the URG flag is set, the XOR encoded bit is 1, otherwise it is 0
        - The bit is decoded by XORing it with the corresponding bit of the xor_code
        - The decoded bit is appended to the current character
        - If the character is complete, it is appended to the decoded message
        - If the character is the terminal dot character, the stop_filter returns True and the sniffing stops
        """
        binary_code = self.convert_string_message_to_binary(xor_code)
        code_index = 0

        decoded_message = ""
        decoded_char = ""

        def is_dot(packet):
            nonlocal decoded_char, decoded_message, binary_code, code_index
            fetched_bit = "1" if "U" in packet[TCP].flags else "0"
            decoded_bit = "1" if fetched_bit == "1" and binary_code[code_index] == "0" or fetched_bit == "0" and binary_code[code_index] == "1" else "0"
            decoded_char += decoded_bit
            code_index += 1
            if len(decoded_char) == 8:
                decoded_message += self.convert_eight_bits_to_character(decoded_char)
                decoded_char = ""
                return decoded_message[-1] == "."
            return False
        
        sniff(filter=filter, stop_filter=is_dot)

        self.log_message(decoded_message, log_file_name)

#    Unfinished code for Arithmetic Coding
#    def get_frequency(self, char):
#        """
#        all_chars distribution:
#        50 spaces, 5 * 26 * 2 letters (lowercase and uppercase), 5 * 10 digits, 3 punctuation marks, 1 termination character
#        50 + 5 * 26 * 2 + 5 * 10 + 3 + 1 = 50 + 260 + 50 + 3 + 1 = 364
#        """
#        if char == " ":
#            return Decimal(50)/Decimal(364)
#        if char in string.ascii_letters or char in string.digits:
#            return Decimal(5)/Decimal(364)
#        if char in ",?!":
#            return Decimal(1)/Decimal(364)

#obj = MyCovertChannel()
#obj.generate_random_binary_message_with_logging("log.txt",100,100)
