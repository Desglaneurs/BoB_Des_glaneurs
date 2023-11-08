# 1. Summary
- Even with the application of SROS2, due to the issue where the data(p[UD]) and guid values used to disconnect between nodes are not encrypted, a vulnerability has been discovered where a malicious attacker can forcibly disconnect a Subscriber and can deny a Subscriber attempting to connect.
- Afterwards, if the attacker sends the packet for disconnecting, which is data(p[UD]), to the Global Data Space (239.255.0.1:7400) using the said Publisher ID, all the Subscribers (Listeners) connected to the Publisher (Talker) will not receive any data and their connection will be disconnected. Moreover, if this disconnection packet is sent continuously, the Subscribers (Listeners) trying to connect will not be able to do so.

# 2. Details
- **Analysis Packet**
    - I put the related packtet file on our github. [LINK](https://github.com/Desglaneurs/BoB_Des_glaneurs/tree/main/Disconnect/uftrace%20and%20pcap)
    - In SROS2, there was a problem where packets sent to the Global Data Space area (e.g., Participant ID) were not encrypted.
    - As a result, an attacker within the same Global Data Space can eavesdrop on the Publisher's Participant ID.
    - Furthermore, if one can obtain the Publisher's Participant ID, it's possible to impersonate that specific node. Therefore, when an attacker sends tampered packets like data(p[UD]) using the acquired Participant ID, proper verification was not carried out.
      
        ![image](https://user-images.githubusercontent.com/146199020/277167680-491ec812-2d81-45c7-937d-8c6834425fce.png)
        
    - **before the attack**
        - When the Publisher (192.168.177.151) sends a packet, the Subscriber (192.168.177.153) sends a response packet.
            ![image](https://user-images.githubusercontent.com/146199020/277167775-8865d360-1791-4276-a516-dd38136d74c2.png)
            
    - **after an attack**
        - The Publisher (192.168.177.151) sends a packet to the Subscriber (192.168.177.153), but there is no response.
            ![image](https://user-images.githubusercontent.com/146199020/277167838-b5b07ecf-cbbc-45f1-b0ed-40804bf73fde.png)
            

# 3. PoC
- **Attack Environment Required Info**
    - Operating System : Ubuntu 20.04 ~ 22.04 LTS
    - ROS2 IRON (192.168.177.151, 192.168.177.153)
    - The attack was successful in both the source code build (release mode) and the packaged environment.
    - [Attacker]
        - While in RTPS communication with SROS2 applied, packets being sent to the Global Data Space (239.255.0.1:7400) are sniffed. After that, using Scapy, a packet named data(p[UD]) which terminates the connection (by referencing guid, src IP, sport) is generated. Following this, the data(p[UD]) packet is dispatched to the Global Data Space.
    - [Victim]
        - All Subscribers (Listeners) connected to the Publisher (Talker) are unable to receive data and are forcibly disconnected.
    - We reported PoC to FastDDS vendor.

- **FastDDS Version**
    - Successful exploitation in all ROS2 versions
        
        | ROS2 Version | FastDDS | RMW - FastDDS | Attack Result |
        | --- | --- | --- | --- |
        | IRON | 2.10.2-1 | 7.1.1-2 | O |
        | HUMBLE | 2.6.6-1 | 6.2.3.1 | O |
        | GALACTIC | 2.3.6-6 | 5.0.2-1 | O |
        | FOXY | 2.1.4-1 | 1.3.2-1 | O |

# 4. Impact
- A remote attacker can forcibly disconnect the Subscriber, and once disconnected, reconnection does not occur.
![image](https://user-images.githubusercontent.com/146199020/277168620-03a1c130-d656-4ca9-8ec5-413314f774e5.png)
