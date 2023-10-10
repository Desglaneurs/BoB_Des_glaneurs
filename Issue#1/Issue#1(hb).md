
# 공격 요약

- **전제 조건**
    - ROS2 통신프로토콜 중 QoS가 Reliable 모드로 설정으로 동작하는 상태여야 합니다.
    
           ⇒ Reliable Mode는 Heartbeat 패킷 기반으로 누락된 메시지들을 다시 요청
    
    - 공격자는 Publisher와 Subscriber가 통신 하는 네트워크 상에 존재 해야하고 패킷 스니핑을 통하여 기존의 통신흐름을 가로챌 수 있어야 합니다.
        
        
- **공격 내용**
    - 공격자는 Publisher(Talker)와 Subscriber(Listener)간의 RTPS 패킷을 스니핑 한 후, Scapy 도구를 사용하여 `**guid-prefix, src IP, dst IP, sport, dport, submessageID: HEARTBEAT(flag, octetsToNextHeader, reader/writerEntityId)**`의 값을 스푸핑 합니다.
    - 이후 HeartBeat 메시지 내의 Sequence Number를 악의적으로 매우 높은 Sequence Number로 조작하여 Subscriber에게 재 전송 합니다. 이 결과로 Subscriber에 전송되는 Publisher의 데이터는 모두 유실됩니다.
        - 1,2,3,4... 증가하는 Sequence Number를 공격자가 50으로 조작한 뒤 패킷을 보내면, 5~49까지의 데이터 내용은 Subscriber가 받지 못하고 유실되며, 50 이후의 정상 데이터를 다시 수신받습니다.
    - 공격을 당한 Subscriber는 이후에 Publisher의 데이터를 수신 하지 못합니다.
