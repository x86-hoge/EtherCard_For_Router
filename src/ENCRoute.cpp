#include "ENCRoute.h"

ENCRoute router;

uint8_t protocol_type = 0;

//バッファの長さ
static uint16_t buffer_len;

static uint8_t icmp_left[MAX_CONNECT_ENC28J60] = {};
static uint8_t arp_left[MAX_CONNECT_ENC28J60]  = {};


const PROGMEM uint8_t led_r[] = {1, 0, 1, 0, 1, 0, 1, 0};
const PROGMEM uint8_t led_g[] = {1, 1, 0, 0, 1, 1, 0, 0};
const PROGMEM uint8_t led_b[] = {1, 1, 1, 1, 0, 0, 0, 0};


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


void ENCRoute::show_mac(uint8_t* mac) {
    char outStr[50];
    sprintf(outStr, "mac_addr : %d::%d::%d::%d::%d::%d", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    Serial.println(outStr);
}

void ENCRoute::show_ip(uint8_t* ip) {
    char outStr[30];
    sprintf(outStr, "ip_addr : %d,%d,%d,%d", ip[0],ip[1],ip[2],ip[3]);
    Serial.println(outStr);
}



void ENCRoute::lightProtocol() {
  digitalWrite(5, led_r[protocol_type]);
  digitalWrite(6, led_g[protocol_type]);
  digitalWrite(7, led_b[protocol_type]);
}

void ENCRoute::checkProtocol() {
  uint8_t ether_type_h = buffer[12];
  uint8_t ether_type_l = buffer[13];
  if (ether_type_h == ETHTYPE_IP_H_V && ether_type_l == ETHTYPE_IP_L_V) {
    if (buffer[23] == 0x01) {
      protocol_type = 2;//icmp
    }
    else if (buffer[23] == 0x06) {
      protocol_type = 3;//tcp
    }
    else if (buffer[23] == 0x17) {
      protocol_type = 4;//udp
    }
  }
  else if (ether_type_h == ETHTYPE_ARP_H_V && ether_type_l == ETHTYPE_ARP_L_V) {
    protocol_type = 1;//arp
  }
}

void ENCRoute::check_arp() {
  if (buffer[ETH_ARP_OPCODE_L_P] == ETH_ARP_OPCODE_REQ_L_V) {
    for (int i = 0; i < IP_LEN; i++) {
      if (buffer[ETH_ARP_DST_IP_P + i] != ip[select_ether][i])return;
    }
    //create arp reply packet
    //========= L2 ===========
    uint8_t target_ip[4];
    uint8_t target_mac[6];
    //copy src ip and mac
    for (int i = 0; i < IP_LEN; i++)target_ip[i] = buffer[ETH_ARP_SRC_IP_P + i];
    for (int i = 0; i < MAC_LEN; i++)target_mac[i] = buffer[ETH_ARP_SRC_MAC_P + i];
    for (int i = 0; i < MAC_LEN; i++)buffer[i] = target_mac[i];
    for (int i = 0; i < MAC_LEN; i++)buffer[6 + i] = mac[select_ether][i];
    //==========ARP===========
    buffer[ETH_ARP_OPCODE_L_P] = ETH_ARP_OPCODE_REPLY_L_V;
    for (int i = 0; i < IP_LEN; i++)buffer[ETH_ARP_DST_IP_P + i] = target_ip[i];
    for (int i = 0; i < MAC_LEN; i++)buffer[ETH_ARP_DST_MAC_P + i] = target_mac[i];
    
    for (int i = 0; i < IP_LEN; i++)buffer[ETH_ARP_SRC_IP_P + i] = ip[select_ether][i];
    for (int i = 0; i < MAC_LEN; i++)buffer[ETH_ARP_SRC_MAC_P + i] = mac[select_ether][i];
    packetSend(buffer_len);
  }
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

/* int memcmp(const void*, const void*, size_t) */
bool ENCRoute::isMe() {
    void* bufferIp  = buffer[IP_DST_P];
    void* currentIp = ip[select_ether];
    return memcmp(bufferIp,currentIp,IP_LEN);
}

void ENCRoute::rep_icmp() {
  if (isMe()) {
    if (icmp_left[select_ether] <= 0)
      icmp_left[select_ether] = ICMP_REPLY_NUM;
    icmp_left[select_ether] --;
    uint8_t target_ip[IP_LEN];
    uint8_t target_mac[MAC_LEN];
    //copy src ip and mac
    memcpy(target_ip,(void*)buffer[IP_SRC_P], IP_LEN);
    //for (uint8_t i = 0; i < IP_LEN; i++)target_ip[i] = buffer[IP_SRC_P + i];
    memcpy(target_mac,(void*)buffer[6], MAC_LEN);
    //for (uint8_t i = 0; i < MAC_LEN; i++)target_mac[i] = buffer[6 + i];
    show_mac(target_mac);
    show_ip(target_ip);
    //========= L2 ===========
    for (uint8_t i = 0; i < MAC_LEN; i++)buffer[i] = target_mac[i];
    for (uint8_t i = 0; i < MAC_LEN; i++)buffer[6 + i] = mac[select_ether][i];
    //========= L3 ===========
    for (uint8_t i = 0; i < IP_LEN; i++)buffer[IP_DST_P + i] = target_ip[i];
    for (uint8_t i = 0; i < IP_LEN; i++)buffer[IP_SRC_P + i] = ip[select_ether][i];
    //=========ICMP===========
    //パケット応答
    buffer[ICMP_TYPE_P] = ICMP_TYPE_ECHOREPLY_V;
    //チェックサムの削除
    buffer[ICMP_CHECKSUM_H_P] = 0x00; buffer[ICMP_CHECKSUM_L_P] = 0x00;
    //IPの長さ
    uint16_t ip_data_len = (((uint16_t)buffer[IP_TOTLEN_H_P]) << 8) | ((uint16_t)buffer[IP_TOTLEN_L_P]);
    ip_data_len -= 20;//L3ヘッダ部分をひく
    //チェックサム計算
    uint16_t result_checksum = checksum(ICMP_TYPE_P, ip_data_len);

    //チェックサム書き込み
    buffer[ICMP_CHECKSUM_H_P] = (uint8_t)(result_checksum >> 8);
    buffer[ICMP_CHECKSUM_L_P] = (uint8_t)result_checksum;
    Serial.println("send icmp");
    Serial.print("counter::"); Serial.println(icmp_left[select_ether]);
    packetSend(buffer_len);
  }
}

void ENCRoute::check_tcp() {
  if (isMe()) {
    if (buffer[TCP_DST_PORT_H_P] == 0x00 && buffer[TCP_DST_PORT_L_P] == 0x80)return;
    if (buffer[TCP_FLAGS_P] == TCP_FLAGS_SYN_V) {
      uint8_t target_ip[IP_LEN]; uint8_t target_mac[MAC_LEN];

      //IPとMACアドレスをコピー
      for (uint8_t i = 0; i < IP_LEN; i++)target_ip[i] = buffer[IP_SRC_P + i];
      for (uint8_t i = 0; i < MAC_LEN; i++)target_mac[i] = buffer[6 + i];
      
      show_mac(target_mac);
      show_ip(target_ip);
      
      //========= L2 ===========
      for (uint8_t i = 0; i < MAC_LEN; i++)buffer[i] = target_mac[i];
      for (uint8_t i = 0; i < MAC_LEN; i++)buffer[6 + i] = mac[select_ether][i];
      //========= L3 ===========
      for (uint8_t i = 0; i < IP_LEN; i++)buffer[IP_DST_P + i] = target_ip[i];
      for (uint8_t i = 0; i < IP_LEN; i++)buffer[IP_SRC_P + i] = ip[select_ether][i];
      //========= L4 ===========
      uint8_t src_port_h = buffer[TCP_SRC_PORT_H_P];
      uint8_t src_port_l = buffer[TCP_SRC_PORT_L_P];
    }
  }
}


void ENCRoute::show_test() {
  Serial.println("==========================================");
  Serial.println(select_ether);
  Serial.println(gNextPacketPtr[select_ether]);
  Serial.println(unreleasedPacket[select_ether]);
  Serial.println("==========================================");
}

void ENCRoute::transferData() {
  uint8_t buffer2[500]; uint16_t buffer2_len = 0;
  change_selectPin();
  uint8_t dst_ip[IP_LEN];
  uint8_t dst_network[IP_LEN];
  for (uint8_t i = 0 ; i < IP_LEN; i++) {
    dst_ip[i] = buffer[IP_DST_P + i];
    dst_network[i] = dst_ip[i] & subnet[select_ether][i];
  }
  show_ip(dst_ip);
  show_ip(dst_network);
  bool s = true;
  for(uint8_t i=0; i<IP_LEN; i++)
    if(dst_network[i] != network[select_ether][i])s = false;
  Serial.println(s);
  if (s)
  {
    if (arp_table_len != 0) {
      for (uint8_t i; i < arp_table_len; i += 10) {
        if (arp_table[i] == dst_ip[i] && arp_table[i + 1] == dst_ip[i + 1] &&
            arp_table[i + 2] == dst_ip[i + 2] && arp_table[i + 3] == dst_ip[i + 3]) {
          for (uint8_t i = 0; i < MAC_LEN; i++)buffer[ETH_DST_MAC + i] = arp_table[4 + i];
          for (uint8_t i = 0; i < MAC_LEN; i++)buffer[ETH_SRC_MAC + i] = mac[select_ether][i];
          packetSend(buffer_len);
        }
      }
    }
    else {
      Serial.println("create arp request");
      //ARPリクエスト作成
      if (sizeof buffer2 < buffer_len)return;
      for (uint8_t i = 0; i < buffer_len; i++)buffer2[i] = buffer[i];
      buffer2_len = buffer_len;
      for (uint8_t i = 0; i < MAC_LEN; i++)buffer[ETH_DST_MAC + i] = 0xff; //ブロードキャスト
      for (uint8_t i = 0; i < MAC_LEN; i++)buffer[ETH_SRC_MAC + i] = buffer2[6 + i]; //送信元
      buffer[ETH_TYPE_H_P] = ETHTYPE_ARP_H_V;
      buffer[ETH_TYPE_L_P] = ETHTYPE_ARP_L_V;
      buffer[ETH_ARP_P] = 0x00; buffer[ETH_ARP_P + 1] = 0x01;
      buffer[ETH_ARP_P + 2] = 0x08; buffer[ETH_ARP_P + 3] = 0x00;
      buffer[ETH_ARP_P + 4] = 0x06; buffer[ETH_ARP_P + 5] = 0x04;
      buffer[ETH_ARP_OPCODE_H_P] = 0x00; buffer[ETH_ARP_OPCODE_L_P] = 0x01;
      for (uint8_t i = 0; i < IP_LEN; i++)buffer[ETH_ARP_SRC_IP_P + i]    = ip[select_ether][i];
      for (uint8_t i = 0; i < MAC_LEN; i++)buffer[ETH_ARP_SRC_MAC_P + i]   = mac[select_ether][i];

      for (uint8_t i = 0; i < MAC_LEN; i++)buffer[ETH_ARP_DST_MAC_P + i] = 0x00;
      for (uint8_t i = 0; i < IP_LEN; i++)buffer[ETH_ARP_DST_IP_P + i]    = dst_ip[i];
      packetSend(60);
      uint8_t count = 3;
      while (1) {
        if (count <= 0)break;
        buffer_len = packetReceive();//パケット受け取り
        if (buffer_len != 0) {
          checkProtocol();
          if (protocol_type == ARP)
            if (buffer[ETH_ARP_OPCODE_L_P] == ETH_ARP_OPCODE_REPLY_L_V) {
              uint8_t src_ip[IP_LEN] = {}; uint8_t src_mac[MAC_LEN] = {};
              Serial.print("reply packet ");
              for (uint8_t i = 0; i < IP_LEN; i++) {
                arp_table[arp_table_len + i] = buffer[ETH_ARP_SRC_IP_P + i];
                src_ip[i] = buffer[ETH_ARP_SRC_IP_P + i];
              }
              for (uint8_t i = 0; i < MAC_LEN; i++) {
                arp_table[arp_table_len + 4 + i] = buffer[ETH_ARP_SRC_MAC_P + i];
                src_mac[i] = buffer[ETH_ARP_SRC_MAC_P + i];
              }
              arp_table_len += 10;
              for (uint8_t i = 0; i < buffer2_len; i++)buffer[i] = buffer2[i];
              for (uint8_t i = 0; i < MAC_LEN; i++)buffer[ETH_DST_MAC + i] = arp_table[4 + i];
              for (uint8_t i = 0; i < MAC_LEN; i++)buffer[ETH_SRC_MAC + i] = mac[select_ether][i];
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
void ENCRoute::start(){
    buffer_len = ENC28J60::packetReceive();//パケット受け取り
    if (buffer_len) {
      Serial.println(buffer_len);
      checkProtocol(); //パケットを解析
      switch (protocol_type) {
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
      if (!isMe())transferData();
    }
    if (icmp_left[ENC28J60::select_ether] <= 0) {
      ENC28J60::change_selectPin();
    }
}