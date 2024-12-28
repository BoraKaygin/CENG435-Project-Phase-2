# Covert Storage Channel that exploits Protocol Field Manipulation using URG Flag field in TCP [Code: CSC-PSV-TCP-URG]

For this phase of the project me and my partner implemented the covert channel mentioned above. Before we dive into the details of our specific implementation, here's some background information on covert channels and the technique we will be using:

## What is a Covert Channel?
A **covert channel** is a method of communication that bypasses normal security mechanisms to transmit information in unintended or unauthorized ways. These channels exploit side effects or unused resources in a system, such as timing delays or unused protocol fields, to encode and transfer data between parties. Covert channels are often studied in cybersecurity to understand and prevent unauthorized information leakage.

### Types of Covert Channels
Covert channels are classified into two main types:
- **Covert Timing Channels**: These manipulate the timing or ordering of events, such as delays between packets, to encode information.
- **Covert Storage Channels**: These embed information within unused or less-noticed fields of protocols, headers, or metadata.

---

## What is a Covert Storage Channel?
A **covert storage channel** hides information within legitimate storage locations in system protocols or packet fields. Unlike timing channels, this approach focuses on manipulating data fields without altering the system's operational behavior. Examples include modifying packet sizes, unused protocol fields, or packet bursts to encode data.

---

## Protocol Field Manipulation Technique
The **Protocol Field Manipulation** technique is a covert storage channel implementation that encodes information by exploiting specific fields in network protocol headers. For instance, the sender can modify fields such as the IP identification field, TCP sequence number, or unused flags to hide data. The receiver retrieves this data by analyzing the altered fields.

### Characteristics of Protocol Field Manipulation:
- **Stealth**: It leverages legitimate protocol fields, making detection challenging.
- **Encoding Strategy**: Fields are altered in a way that represents binary data (e.g., a value below a certain threshold may represent '0', and above it, '1').
- **Constraints**: Only allowable values for protocol fields are used, adhering to protocol specifications to avoid invalid packets.
- **Consensus**: Both sender and receiver must agree on how fields are encoded and decoded.

This technique is powerful for covert communication but requires careful design to ensure the system's normal functionality remains unaffected.

---

# Our implementation:
As mentioned before, we implemented a covert storage channel exploiting protocol field manipulation, specifically the URG flag field in TCP.

- **TCP (Transmission Control Protocol)** is a reliable, connection-oriented protocol that ensures accurate data delivery between devices over a network by establishing and maintaining a connection, handling retransmissions, and ordering data packets.

- The **URG flag** in TCP (Urgent Pointer field) indicates that the data contained in the segment is urgent, and the receiving system should prioritize processing it, with the urgent pointer specifying the end of the urgent data within the segment.

The URG flag is actually not that commonly used, and for our project we could set it without handling any "urgency" or "prioritization", it simply served as a 1 bit field we could use for transfering data one bit at a time. But we couldn't send the message directly, we instead had to encode the data at the sender and then decode it at the receiver.

To do this we chose a simple XOR encoding/decoding technique. The XOR operation is associative, self inverse.
- Self inverse means any number XOR'ed with itself will evaluate to 0.
This is handy for our purposes since:
- 0 is the indentity element for XOR, any number XOR'ed with 0 will remain unchanged.

With this in mind, what we do to encode and decode our message is simple.
1. Pick a value and give it to both sender and receiver, let's call this value X.
2. Let's call our message M, before we send M we XOR it with X and transmit X^M bit by bit. (^ being the XOR symbol)
3. Our TCP packets travel to the receiver, their URG flag fields carrying single bits forming X^M. Even if someone was listening to this traffic and checking the URG fields of our packets, they wouldn't be able to read our message, as it will look like random data.
4. The receiver receives the packets and reconstructs the X^M value bit by bit, then XOR's it with X, just like the sender did.
5. The resulting value is X^M^X = M^(X^X) = M^0 = M, our original message!

## Parameters
To achieve this we randomly generated a 100 character string using the given methods and gave it to both send and receive methods through config.json. So our implementation will be able to encode and send any message that is 800 bits or shorter. Sending a shorter message will not cause problems because the receiver decodes the message character by character and will stop receiving once the terminal dot character is decoded. A longer message can be sent by simply giving a longer xor_code parameter.

The other parameters are simply to establish communication between sender and receiver in the senders case, and sniffing the correct packets in the receivers case.

## Channel Capacity
This channel implementation transmits messages at roughly 10.4 bits per second. This is basically the packet sending rate as we are transmiting exactly 1 bit per packet. Higher speeds can be achieved by also doing compression, we wanted to experiment with other encoding methods such as Arithmetic Coding, which maps every possible message to a real number in range [0,1), but we didn't have enough time. This coding method maps a bigger value range to more common messages, meaning less precision required and less bits transmitted for messages with more common characters.