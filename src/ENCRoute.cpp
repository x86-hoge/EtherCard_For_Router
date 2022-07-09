#include "ENCRoute.h"

ENCRoute router;

uint8_t protocol_type = 0;

//バッファの長さ
static uint16_t buffer_len;

static uint8_t icmp_left[MAX_CONNECT_ENC28J60] = {};
static uint8_t  arp_left[MAX_CONNECT_ENC28J60] = {};

static uint8_t* bp = ENC28J60::buffer;
static uint8_t* atp = ENCRoute::arp_table;


enum STATUS {
    CONNECTED,
};

enum PROTOCOL {
    ARP = 1,
    ICMP,
    TCP,
    UDP,
};

enum INTERFACE {
    ETH0,
    ETH1,
};

void ENCRoute::showMac(uint8_t* mac) {
    char outStr[50];
    sprintf(outStr, "MAC_ADDR : %d::%d::%d::%d::%d::%d", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    Serial.println(outStr);
}

void ENCRoute::showIp(uint8_t* ip) {
    char outStr[30];
    sprintf(outStr, "IP_ADDR : %d,%d,%d,%d", ip[0],ip[1],ip[2],ip[3]);
    Serial.println(outStr);
}

void ENCRoute::showTest() {
    Serial.println("==========================================");
    Serial.println(select_ether);
    Serial.println(gNextPacketPtr[select_ether]);
    Serial.println(unreleasedPacket[select_ether]);
    Serial.println("==========================================");
}

uint8_t ENCRoute::checkProtocol() {
    uint8_t ether_type_h = buffer[12];
    uint8_t ether_type_l = buffer[13];
    uint8_t protocol = buffer[23];
    uint8_t returnNo = 0;
    if (ether_type_h == ETHTYPE_IP_H_V && ether_type_l == ETHTYPE_IP_L_V) {
        switch(protocol){
            case 0x01: returnNo = ICMP; 
            case 0x06: returnNo = TCP;
            case 0x17: returnNo = UDP;
        }
    }
    else if (ether_type_h == ETHTYPE_ARP_H_V && ether_type_l == ETHTYPE_ARP_L_V) {
        returnNo = 1;//arp
    }
    return returnNo;
}

void ENCRoute::check_arp() {
    if (buffer[ETH_ARP_OPCODE_L_P] == ETH_ARP_OPCODE_REQ_L_V && !ipcmp(bp+ETH_ARP_DST_IP_P,ip[select_ether])) { return; }

    /*============= L2 ===============*/
    uint8_t target_ip[IP_LEN];
    uint8_t target_mac[MAC_LEN];

    /* 送信元IP・MACをコピー */
    ipcpy(target_ip,bp+ETH_ARP_SRC_IP_P);
    maccpy(target_mac,bp+ETH_ARP_SRC_MAC_P);
    
    maccpy(bp,target_mac);
    maccpy(bp+MAC_LEN,mac[select_ether]);

    /*============ =ARP ==============*/
    buffer[ETH_ARP_OPCODE_L_P] = ETH_ARP_OPCODE_REPLY_L_V;
    ipcpy(bp+ETH_ARP_DST_IP_P,target_ip);
    maccpy(bp+ETH_ARP_DST_MAC_P,target_mac);

    ipcpy(bp+ETH_ARP_SRC_IP_P, ip[select_ether]);
    maccpy(bp+ETH_ARP_SRC_MAC_P, mac[select_ether]);

    packetSend(buffer_len);

}



uint16_t ENCRoute::checksum(uint8_t addr, uint16_t len) {
    uint32_t ret = 0x000000;
    for (int i = 0; i < len; i += 2) {
    ret += (((uint32_t)buffer[addr + i] ) << 8);
    if (i + 1 > len)break;
    ret += ((uint32_t)buffer[addr + i + 1]);
    }
    ret = (ret & 0x00ffff) + (ret >> 16);
    ret = (ret & 0x00ffff) + (ret >> 16);
    return (uint16_t)~ret;
}

bool ENCRoute::ipcmp(void* src,void* dst){ return memcmp(src,dst,IP_LEN); }

bool ENCRoute::maccmp(void* src,void* dst){ return memcmp(src,dst,MAC_LEN); }


void ENCRoute::ipcpy(void* src,void* dst){ memcpy(src,dst, IP_LEN); }

void ENCRoute::maccpy(void* src,void* dst){ memcpy(src,dst, MAC_LEN); }

bool ENCRoute::isMe() { return ipcmp(bp+IP_DST_P,ip[select_ether]); }

void ENCRoute::rep_icmp() {
    if (isMe()) {
    if (icmp_left[select_ether] <= 0){ icmp_left[select_ether] = ICMP_REPLY_NUM; }
        
    icmp_left[select_ether] --;

    uint8_t target_ip[IP_LEN];
    uint8_t target_mac[MAC_LEN];
    uint8_t* tip= target_ip;
    uint8_t* tmac= target_mac;

    /* IPとMACアドレスをコピー */
    ipcpy(tip,bp+IP_SRC_P);
    maccpy(tmac,bp+6);

    showMac(target_mac);
    showIp(target_ip);

    /*============= L2 ===============*/
    maccpy(bp,tmac);
    maccpy(bp+6,tmac);

    /*============= L3 ===============*/
    ipcpy(bp+IP_DST_P,tip);
    ipcpy(bp+IP_SRC_P,ip[select_ether]);

    /*=============ICMP===============*/
    /* パケット応答 */
    buffer[ICMP_TYPE_P] = ICMP_TYPE_ECHOREPLY_V;

    /* チェックサムの削除 */
    buffer[ICMP_CHECKSUM_H_P] = 0x00; 
    buffer[ICMP_CHECKSUM_L_P] = 0x00;

    /* IPの長さ */
    uint16_t ip_data_len = (((uint16_t)buffer[IP_TOTLEN_H_P]) << 8) | ((uint16_t)buffer[IP_TOTLEN_L_P]);
    ip_data_len -= 20;//L3ヘッダ部分をひく

    /* チェックサム計算 */
    uint16_t result_checksum = checksum(ICMP_TYPE_P, ip_data_len);

    /* チェックサム書き込み */
    buffer[ICMP_CHECKSUM_H_P] = (uint8_t)(result_checksum >> 8);
    buffer[ICMP_CHECKSUM_L_P] = (uint8_t)result_checksum;
    Serial.println("send icmp");
    Serial.print("counter::"); Serial.println(icmp_left[select_ether]);
    packetSend(buffer_len);
    }
}

void ENCRoute::check_tcp() {
    if (isMe()) {
        if (buffer[TCP_DST_PORT_H_P] == 0x00 && buffer[TCP_DST_PORT_L_P] == 0x80){ return; }

        if (buffer[TCP_FLAGS_P] == TCP_FLAGS_SYN_V) {

            uint8_t target_ip[IP_LEN]; 
            uint8_t target_mac[MAC_LEN];
            uint8_t* tip= target_ip;
            uint8_t* tmac= target_ip;

            /* IPとMACアドレスをコピー */
            ipcpy(tip,bp+IP_SRC_P);
            maccpy(tmac,bp+6);

            showMac(target_mac);
            showIp(target_ip);

            /*============= L2 ===============*/
            maccpy(bp,tmac);
            maccpy(bp+6,mac[select_ether]);

            /*============= L3 ===============*/
            ipcpy(bp+IP_DST_P,tip);
            ipcpy(bp+IP_SRC_P,ip[select_ether]);

            /*============= L4 ===============*/
            uint8_t src_port_h = buffer[TCP_SRC_PORT_H_P];
            uint8_t src_port_l = buffer[TCP_SRC_PORT_L_P];  
        }
    }
}

void ENCRoute::transferData() {
    uint8_t buffer2[500]; 
    uint16_t buffer2_len = 0;
    uint8_t* b2p=buffer2;
    change_selectPin();
    uint8_t dst_ip[IP_LEN];
    uint8_t dst_network[IP_LEN];
    
    for (uint8_t i = 0 ; i < IP_LEN; i++) { dst_network[i] = dst_ip[i] & subnet[select_ether][i]; }
    ipcpy(dst_ip,bp+IP_DST_P);
    ipcpy(dst_network,dst_ip & subnet[select_ether]);
    showIp(dst_ip);
    showIp(dst_network);
    bool s = true;
    s = ipcmp(dst_network,network[select_ether]);
    Serial.println(s);
    if (s) {
        
        if (arp_table_len != 0) {
            for (uint8_t i; i < arp_table_len; i += 10) {
                if (ipcmp(dst_ip,atp+i)) {
                    maccpy(bp+ETH_DST_MAC,atp+IP_LEN);//送信先
                    maccpy(bp+ETH_SRC_MAC,mac[select_ether]);//送信元
                    packetSend(buffer_len);
                }
            }
        }
        
        Serial.println("create arp request");
        //ARPリクエスト作成
        if (sizeof buffer2 < buffer_len)return;
        memcpy(b2p,bp,buffer_len);
        buffer2_len = buffer_len;

        memset(bp+ETH_DST_MAC,0xff,MAC_LEN);//ブロードキャスト
        maccpy(bp+ETH_SRC_MAC,b2p+6); //送信元

        buffer[ETH_TYPE_H_P]  = ETHTYPE_ARP_H_V;
        buffer[ETH_TYPE_L_P]  = ETHTYPE_ARP_L_V;
        buffer[ETH_ARP_P]     = 0x00; buffer[ETH_ARP_P + 1] = 0x01;
        buffer[ETH_ARP_P + 2] = 0x08; buffer[ETH_ARP_P + 3] = 0x00;
        buffer[ETH_ARP_P + 4] = 0x06; buffer[ETH_ARP_P + 5] = 0x04;
        buffer[ETH_ARP_OPCODE_H_P] = 0x00; buffer[ETH_ARP_OPCODE_L_P] = 0x01;

        ipcpy(bp+ETH_ARP_SRC_IP_P, ip[select_ether]);
        maccpy(bp+ETH_ARP_SRC_MAC_P,mac[select_ether]);

        memset(bp+ETH_ARP_DST_MAC_P,0x00,MAC_LEN);
        ipcpy(buffer+ETH_ARP_DST_IP_P,dst_ip);
        packetSend(60);
        uint8_t count = 3;

        while (1) {
            if (count <= 0){ break; }

            buffer_len = packetReceive();//パケット受け取り
            
            if (buffer_len != 0) {
                if ( checkProtocol() == ARP)
                if (buffer[ETH_ARP_OPCODE_L_P] == ETH_ARP_OPCODE_REPLY_L_V) {
                    uint8_t src_ip[IP_LEN] = {}; 
                    uint8_t src_mac[MAC_LEN] = {};
                    Serial.print("reply packet ");
    
                    maccpy(atp+arp_table_len,bp+ETH_ARP_SRC_IP_P);
                    ipcpy(src_ip,bp+ETH_ARP_SRC_IP_P);
    
                    maccpy(atp+arp_table_len+IP_LEN,bp+ETH_ARP_SRC_MAC_P);
                    maccpy(src_mac,bp+ETH_ARP_SRC_MAC_P);
    
                    arp_table_len += 10;
                    memcpy(bp,b2p,buffer2_len);//バッファをコピー
                    maccpy(bp+ETH_DST_MAC,atp+4);
                    maccpy(bp+ETH_SRC_MAC,mac[select_ether]);
                    
                    packetSend(buffer_len);
                    return;
                }
            }
            count--;
        }
    }
    /*
        if (routing_table_len != 0) {
         bool find_ip = false;
         for (uint8_t i = 0 ; i < 50; i += 5){
             if(routing_table[i+0] == select_ether){
                 routing
             }
             }

         }
    */
    }
}

void ENCRoute::update(){
    buffer_len = ENC28J60::packetReceive();//パケット受け取り
    if (buffer_len) {
        Serial.println(buffer_len);
        switch (checkProtocol()) {
        case ARP:
            check_arp();
            return;
        case ICMP:
            Serial.println("get icmp");
            rep_icmp();
            break;
            //case 3:
            //check_tcp();
            //break;
        }
        if (!isMe()){ transferData(); }
    }
    if (icmp_left[select_ether] <= 0) { change_selectPin(); }
}