#import string
from CovertChannelBase import CovertChannelBase
from scapy.all import IP, TCP, sniff
import decimal
from decimal import Decimal
import time
import struct

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

    char_probs_table = {}

    def create_probs_table(self, frequency_dict):
        #print("Create probs table")
        total = Decimal(sum(frequency_dict.values()))
        #print(total)
        for key in frequency_dict:
            self.char_probs_table[key] = Decimal(frequency_dict[key] / total)
            #print("Char: {}, Prob: {}".format(key, self.char_probs_table[key]))
    
    def generate_next_step_values(self, step_min, step_max):
        step_range = step_max - step_min
        step_values = {}
        cumulative_value = step_min
        for key in self.char_probs_table:
            cumulative_value += step_range * self.char_probs_table[key]
            step_values[key] = [step_min, cumulative_value]
            step_min = cumulative_value
        step_values[list(self.char_probs_table.keys())[-1]][1] = step_max
        return step_values
    
    def float_to_binary(self, value, precision):
        value_scaled = round(value * (2 ** precision["fraction"]))
        return '{:0{}b}'.format(value_scaled, precision["integer"] + precision["fraction"])
    
    def get_value_with_min_bits(self, min_value, max_value, precision):
        min_string = self.float_to_binary(min_value, precision)
        print("Min string:\n{}".format(min_string))
        max_string = self.float_to_binary(max_value, precision)
        print("Max string:\n{}".format(max_string))
        for i in range(sum(precision.values())):
            if max_string[i] != min_string[i]:
                break
        #print("Result string: {}".format(max_string[:i + 1]))
        return max_string[:i + 1]
    
    def encode_message(self, message, precision):
        step_min = Decimal(0)
        step_max = Decimal(1)
        for char in message:
            step_values = self.generate_next_step_values(step_min, step_max)
            #for key in step_values:
            #    print("Char: {}, Min: {}, Max: {}".format(key, step_values[key][0], step_values[key][1]))
            step_min = step_values[char][0]
            step_max = step_values[char][1]
        return self.get_value_with_min_bits(step_min, step_max, precision)


    def send(self, source_ip, destination_ip, destination_port, frequency_dict, precision, min_length, max_length, log_file_name):
        """
        - Each bit is XORed with the corresponding bit of the xor_code in line 29
        - This is done explicitly with an if statement
        - The packet is sent with the URG flag set if the XOR encoded bit is 1, and not set if the bit is 0
        - The commented out code is for testing and benchmarking purposes
        """
        decimal.getcontext().prec = sum(precision.values())
        message = self.generate_random_message(min_length=min_length, max_length=max_length)
        self.log_message(message, log_file_name)
        binary_message = self.convert_string_message_to_binary(message)
        print("Message:\n{}".format(message))
        print("Binary message:\n{}".format(binary_message))
        print("Binary message length: {}".format(len(binary_message)))

        packet_IP = IP(src=source_ip, dst=destination_ip)
        packet_TCP = TCP(dport=destination_port)

        self.create_probs_table(frequency_dict)
        encoded_message = self.encode_message(message, precision)
        print("Encoded message:\n{}".format(encoded_message))
        print("Encoded message length: {}".format(len(encoded_message)))
        
        #start = time.time()
        for bit in encoded_message:
            if bit == "1":
                packet_TCP.flags = "U"
            else:
                packet_TCP.flags = ""
            packet = packet_IP / packet_TCP
            CovertChannelBase.send(self, packet)
        #end = time.time()
        #bps = len(binary_message) / (end - start)
        #print("Sent {} bits in {} seconds. {} bits per second.".format(len(binary_message), end - start, bps))
    
    def binary_to_float(self, binary_string, precision):
        #integer = int(binary_string[:precision["integer"]], 2)
        #fraction = int(binary_string[precision["integer"]:], 2)
        #return Decimal(integer) + Decimal(fraction) / Decimal(2 ** precision["fraction"])
        return Decimal(int(binary_string, 2)) / Decimal(2 ** (len(binary_string)-precision["integer"]))
    
    def find_char(self, value, step_values):
        for key in step_values:
            if value >= step_values[key][0] and value <= step_values[key][1]:
                return key
        print(f"Value: {value:.10f}")
        for key in step_values:
            print(f"Char: {key}, Min: {step_values[key][0]:.10f}, Max: {step_values[key][1]:.10f}")
        raise("Value {} not found in step values".format(value))

    def receive(self, filter, frequency_dict, precision, log_file_name):
        """
        - The packet is received and the URG flag is checked
        - If the URG flag is set, the XOR encoded bit is 1, otherwise it is 0
        - The bit is decoded by XORing it with the corresponding bit of the xor_code
        - The decoded bit is appended to the current character
        - If the character is complete, it is appended to the decoded message
        - If the character is the terminal dot character, the stop_filter returns True and the sniffing stops
        """
        decimal.getcontext().prec = sum(precision.values())

        encoded_message = ""
        decoded_message = ""

        self.create_probs_table(frequency_dict)

        step_min = Decimal(0)
        step_max = Decimal(1)

        step_values = self.generate_next_step_values(step_min, step_max)
        #for key in step_values:
        #    print("Char: {}, Min: {}, Max: {}".format(key, step_values[key][0], step_values[key][1]))

        def is_dot(packet):
            nonlocal encoded_message, decoded_message, step_min, step_max, step_values
            fetched_bit = "1" if "U" in packet[TCP].flags else "0"
            encoded_message += fetched_bit
            #print("Encoded message:\n{}".format(encoded_message))
            current_value = self.binary_to_float(encoded_message, precision)
            #print("Current value: {}".format(current_value))
            current_char = self.find_char(current_value, step_values)
            #print("Current char: {}".format(current_char))
            variant_encoded_message = ""
            if fetched_bit == "1":
                variant_encoded_message = encoded_message[:-1] + "0"
            else:
                variant_encoded_message = encoded_message[:-1] + "1"
            #print("Variant encoded message:\n{}".format(variant_encoded_message))
            variant_value = self.binary_to_float(variant_encoded_message, precision)
            #print("Variant value: {}".format(variant_value))
            variant_char = self.find_char(variant_value, step_values)
            #print("Variant char: {}".format(variant_char))
            if variant_char == current_char:
                decoded_message += current_char
                print("Decoded message:\n{}".format(decoded_message))
                if current_char == ".":
                    return True
                step_min = step_values[current_char][0]
                step_max = step_values[current_char][1]
                step_values = self.generate_next_step_values(step_min, step_max)
            """
            if fetched_bit == "1":
                lower_encoded_message = encoded_message[:-1] + "0"
                lower_value = self.binary_to_float(lower_encoded_message, precision)
                lower_char = self.find_char(lower_value, step_values)
                if lower_char == current_char:
                    decoded_message += current_char
                    if current_char == ".":
                        return True
                    step_min = step_values[current_char][0]
                    step_max = step_values[current_char][1]
                    step_values = self.generate_next_step_values(step_min, step_max)
            else:
                upper_encoded_message = encoded_message[:-1] + "1"
                upper_value = self.binary_to_float(upper_encoded_message, precision)
                upper_char = self.find_char(upper_value, step_values)
                if upper_char == current_char:
                    decoded_message += current_char
                    if current_char == ".":
                        return True
                    step_min = step_values[current_char][0]
                    step_max = step_values[current_char][1]
                    step_values = self.generate_next_step_values(step_min, step_max)
            """
            return False
            
        sniff(filter=filter, stop_filter=is_dot)

        self.log_message(decoded_message, log_file_name)

        """
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
        """
