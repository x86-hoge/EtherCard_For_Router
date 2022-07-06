
#include <ENCRoute.h>
#include <TimerOne.h>

#define ICMP_REPLY_NUM 4
#define BUFFER_SIZE 1500

static uint8_t ip[2][4]  = {{ 192, 168, 1, 1}, {192, 168, 2, 1}}; //IPアドレス

static uint8_t network[2][4]  = {{192, 168, 1, 0,}, {192, 168, 2, 0}}; //ネットワークアドレス
static uint8_t subnet[2][4]  = {{ 255, 255, 255, 0}, {255, 255, 255, 0}}; //サブネットマスク

//MACアドレス
static uint8_t mac[2][6] = {
    {0x13, 0x45, 0x75, 0xF2, 0x1A, 0x1B}, 
    {0x12, 0x10, 0x39, 0x07, 0x11, 0x11}
};

static uint8_t csPin[MAX_CONNECT_ENC28J60] = {8, 9}; //CSピン

static uint8_t protocol_type = 0;//解析したプロトコルの種類

uint8_t ENC28J60::buffer[BUFFER_SIZE]; //バッファ

static uint16_t buffer_len;//バッファの長さ

static uint8_t icmp_left[MAX_CONNECT_ENC28J60] = {};

static uint8_t arp_left[MAX_CONNECT_ENC28J60]  = {};

const uint8_t led_r[] = {1, 0, 1, 0, 1, 0, 1, 0};

const uint8_t led_g[] = {1, 1, 0, 0, 1, 1, 0, 0};

const uint8_t led_b[] = {1, 1, 1, 1, 0, 0, 0, 0};

enum route_status{
  CONNECTED,
};

//[ip addr : 4byte][mac addr : 6byte]
static uint8_t arp_table[100] =
{
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static uint8_t arp_table_len = 0;

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

//[interface][ip addr : 4byte][netmack]
static uint8_t routing_table[60] =
{
  0x00,   0x00, 0x00, 0x00, 0x00,  0x00,
  0x00,   0x00, 0x00, 0x00, 0x00,  0x00,
  0x00,   0x00, 0x00, 0x00, 0x00,  0x00,
  0x00,   0x00, 0x00, 0x00, 0x00,  0x00,
  0x00,   0x00, 0x00, 0x00, 0x00,  0x00,
  0x00,   0x00, 0x00, 0x00, 0x00,  0x00,
  0x00,   0x00, 0x00, 0x00, 0x00,  0x00,
  0x00,   0x00, 0x00, 0x00, 0x00,  0x00,
  0x00,   0x00, 0x00, 0x00, 0x00,  0x00,
  0x00,   0x00, 0x00, 0x00, 0x00,  0x00,
};
static uint8_t routing_table_len = 0;


void show_mac(uint8_t mac[6]) {
  Serial.print("mac : ");
  for (int i = 0; i < 6; i++) {
    Serial.print(mac[i], HEX);
    if (i != 5)Serial.print("::");
  }
  Serial.println("");
}
void show_ip(uint8_t ip[6]) {
  Serial.print("ip : ");
  for (int i = 0; i < 4; i++) {
    Serial.print(ip[i]);
    if (i != 3)Serial.print(",");
  }
  Serial.println("");
}



void light_protcol() {
  digitalWrite(5, led_r[protocol_type]);
  digitalWrite(6, led_g[protocol_type]);
  digitalWrite(7, led_b[protocol_type]);
}

void check_protocol() {
  uint8_t ether_type_h = ether.buffer[12];
  uint8_t ether_type_l = ether.buffer[13];
  if (ether_type_h == ETHTYPE_IP_H_V && ether_type_l == ETHTYPE_IP_L_V) {
    if (ether.buffer[23] == 0x01) {
      protocol_type = 2;//icmp
    }
    else if (ether.buffer[23] == 0x06) {
      protocol_type = 3;//tcp
    }
    else if (ether.buffer[23] == 0x17) {
      protocol_type = 4;//udp
    }
  }
  else if (ether_type_h == ETHTYPE_ARP_H_V && ether_type_l == ETHTYPE_ARP_L_V) {
    protocol_type = 1;//arp
  }
}

void check_arp() {
  if (ether.buffer[ETH_ARP_OPCODE_L_P] == ETH_ARP_OPCODE_REQ_L_V) {
    for (int i = 0; i < 4; i++) {
      if (ether.buffer[ETH_ARP_DST_IP_P + i] != ip[ether.select_ether][i])return;
    }
    //create arp reply packet
    //========= L2 ===========
    uint8_t target_ip[4];
    uint8_t target_mac[6];
    //copy src ip and mac
    for (int i = 0; i < 4; i++)target_ip[i] = ether.buffer[ETH_ARP_SRC_IP_P + i];
    for (int i = 0; i < 6; i++)target_mac[i] = ether.buffer[ETH_ARP_SRC_MAC_P + i];
    for (int i = 0; i < 6; i++)ether.buffer[i] = target_mac[i];
    for (int i = 0; i < 6; i++)ether.buffer[6 + i] = mac[ether.select_ether][i];
    //==========ARP===========
    ether.buffer[ETH_ARP_OPCODE_L_P] = ETH_ARP_OPCODE_REPLY_L_V;
    for (int i = 0; i < 4; i++)ether.buffer[ETH_ARP_DST_IP_P + i] = target_ip[i];
    for (int i = 0; i < 6; i++)ether.buffer[ETH_ARP_DST_MAC_P + i] = target_mac[i];
    for (int i = 0; i < 4; i++)ether.buffer[ETH_ARP_SRC_IP_P + i] = ip[ether.select_ether][i];
    for (int i = 0; i < 6; i++)ether.buffer[ETH_ARP_SRC_MAC_P + i] = mac[ether.select_ether][i];
    ether.packetSend(buffer_len);
  }
}



uint16_t checksum(uint8_t addr, uint16_t len) {
  uint32_t ret = 0x000000;
  for (int i = 0; i < len; i += 2) {
    ret += (((uint32_t)ether.buffer[addr + i] ) << 8);
    if (i + 1 > len)break;
    ret += ((uint32_t)ether.buffer[addr + i + 1]);
  }
  ret = (ret & 0x00ffff) + (ret >> 16);
  ret = (ret & 0x00ffff) + (ret >> 16);
  return (uint16_t)~ret;
}

bool is_me() {
  for (int i = 0; i < 4; i++) {
    if (ether.buffer[IP_DST_P + i] != ip[ether.select_ether][i])return false;
  }
  return true;
}

void rep_icmp() {
  if (is_me()) {
    if (icmp_left[ether.select_ether] <= 0)
      icmp_left[ether.select_ether] = ICMP_REPLY_NUM;
    icmp_left[ether.select_ether] --;
    uint8_t target_ip[4];
    uint8_t target_mac[6];
    //copy src ip and mac
    for (uint8_t i = 0; i < IP_LEN; i++)target_ip[i] = ether.buffer[IP_SRC_P + i];
    for (uint8_t i = 0; i < 6; i++)target_mac[i] = ether.buffer[6 + i];
    show_mac(target_mac);
    show_ip(target_ip);
    //========= L2 ===========
    for (uint8_t i = 0; i < 6; i++)ether.buffer[i] = target_mac[i];
    for (uint8_t i = 0; i < 6; i++)ether.buffer[6 + i] = mac[ether.select_ether][i];
    //========= L3 ===========
    for (uint8_t i = 0; i < IP_LEN; i++)ether.buffer[IP_DST_P + i] = target_ip[i];
    for (uint8_t i = 0; i < IP_LEN; i++)ether.buffer[IP_SRC_P + i] = ip[ether.select_ether][i];
    //=========ICMP===========
    //パケット応答
    ether.buffer[ICMP_TYPE_P] = ICMP_TYPE_ECHOREPLY_V;
    //チェックサムの削除
    ether.buffer[ICMP_CHECKSUM_H_P] = 0x00; ether.buffer[ICMP_CHECKSUM_L_P] = 0x00;
    //IPの長さ
    uint16_t ip_data_len = (((uint16_t)ether.buffer[IP_TOTLEN_H_P]) << 8) | ((uint16_t)ether.buffer[IP_TOTLEN_L_P]);
    ip_data_len -= 20;//L3ヘッダ部分をひく
    //チェックサム計算
    uint16_t result_checksum = checksum(ICMP_TYPE_P, ip_data_len);

    //チェックサム書き込み
    ether.buffer[ICMP_CHECKSUM_H_P] = (uint8_t)(result_checksum >> 8);
    ether.buffer[ICMP_CHECKSUM_L_P] = (uint8_t)result_checksum;
    Serial.println("send icmp");
    Serial.print("counter::"); Serial.println(icmp_left[ether.select_ether]);
    ether.packetSend(buffer_len);
  }
}

void check_tcp() {
  if (is_me()) {
    if (ether.buffer[TCP_DST_PORT_H_P] == 0x00 && ether.buffer[TCP_DST_PORT_L_P] == 0x80)return;
    if (ether.buffer[TCP_FLAGS_P] == TCP_FLAGS_SYN_V) {
      uint8_t target_ip[4]; uint8_t target_mac[6];

      //IPとMACアドレスをコピー
      for (uint8_t i = 0; i < IP_LEN; i++)target_ip[i] = ether.buffer[IP_SRC_P + i];
      for (uint8_t i = 0; i < 6; i++)target_mac[i] = ether.buffer[6 + i];
      
      show_mac(target_mac);
      show_ip(target_ip);
      
      //========= L2 ===========
      for (uint8_t i = 0; i < 6; i++)ether.buffer[i] = target_mac[i];
      for (uint8_t i = 0; i < 6; i++)ether.buffer[6 + i] = mac[ether.select_ether][i];
      //========= L3 ===========
      for (uint8_t i = 0; i < IP_LEN; i++)ether.buffer[IP_DST_P + i] = target_ip[i];
      for (uint8_t i = 0; i < IP_LEN; i++)ether.buffer[IP_SRC_P + i] = ip[ether.select_ether][i];
      //========= L4 ===========
      uint8_t src_port_h = ether.buffer[TCP_SRC_PORT_H_P];
      uint8_t src_port_l = ether.buffer[TCP_SRC_PORT_L_P];
    }
  }
}

void setup() {
  Serial.begin(57600);
  pinMode(5, OUTPUT);
  pinMode(6, OUTPUT);
  pinMode(7, OUTPUT);
  Timer1.initialize(1000000);
  Timer1.attachInterrupt(light_protcol);
  
  ether.initSPI();
  ether.Set_BufferSize(sizeof ENC28J60::buffer);
  for (uint8_t i = 0, rev = 0; i < MAX_CONNECT_ENC28J60; i++) {
    rev = ether.initialize(mac[ether.select_ether], csPin[ether.select_ether]);
    if (rev == 0)
      Serial.println( "Failed to access Ethernet controller");
    Serial.print("revision :B"); Serial.println(rev);
    show_ip(ip[ether.select_ether]);
    show_mac(mac[ether.select_ether]);
    ether.change_selectPin();
  }
  ether.change_selectPin();
//==============================
//ルーティングテーブルに追加
//==============================

}

void show_test() {
  Serial.println("==========================================");
  Serial.println(ether.select_ether);
  Serial.println(ether.gNextPacketPtr[ether.select_ether]);
  Serial.println(ether.unreleasedPacket[ether.select_ether]);
  Serial.println("==========================================");
}

void other_data() {
  Serial.println("get other data");
  uint8_t buffer2[500]; uint16_t buffer2_len = 0;
  ether.change_selectPin();
  uint8_t dst_ip[4];
  uint8_t dst_network[4];
  for (uint8_t i = 0 ; i < 4; i++) {
    dst_ip[i] = ether.buffer[IP_DST_P + i];
    dst_network[i] = dst_ip[i] & subnet[ether.select_ether][i];
  }
  show_ip(dst_ip);
  show_ip(dst_network);
  bool s = true;
  for(uint8_t i=0; i<4; i++)
    if(dst_network[i] != network[ether.select_ether][i])s = false;
  Serial.println(s);
  if (s)
  {
    if (arp_table_len != 0) {
      for (uint8_t i; i < arp_table_len; i += 10) {
        if (arp_table[i] == dst_ip[i] && arp_table[i + 1] == dst_ip[i + 1] &&
            arp_table[i + 2] == dst_ip[i + 2] && arp_table[i + 3] == dst_ip[i + 3]) {
          for (uint8_t i = 0; i < 6; i++)ether.buffer[ETH_DST_MAC + i] = arp_table[4 + i];
          for (uint8_t i = 0; i < 6; i++)ether.buffer[ETH_SRC_MAC + i] = mac[ether.select_ether][i];
          ether.packetSend(buffer_len);
        }
      }
    }
    else {
      Serial.println("create arp request");
      //ARPリクエスト作成
      if (sizeof buffer2 < buffer_len)return;
      for (uint8_t i = 0; i < buffer_len; i++)buffer2[i] = ether.buffer[i];
      buffer2_len = buffer_len;
      for (uint8_t i = 0; i < 6; i++)ether.buffer[ETH_DST_MAC + i] = 0xff; //ブロードキャスト
      for (uint8_t i = 0; i < 6; i++)ether.buffer[ETH_SRC_MAC + i] = buffer2[6 + i]; //送信元
      ether.buffer[ETH_TYPE_H_P] = ETHTYPE_ARP_H_V;
      ether.buffer[ETH_TYPE_L_P] = ETHTYPE_ARP_L_V;
      ether.buffer[ETH_ARP_P] = 0x00; ether.buffer[ETH_ARP_P + 1] = 0x01;
      ether.buffer[ETH_ARP_P + 2] = 0x08; ether.buffer[ETH_ARP_P + 3] = 0x00;
      ether.buffer[ETH_ARP_P + 4] = 0x06; ether.buffer[ETH_ARP_P + 5] = 0x04;
      ether.buffer[ETH_ARP_OPCODE_H_P] = 0x00; ether.buffer[ETH_ARP_OPCODE_L_P] = 0x01;
      for (uint8_t i = 0; i < 4; i++)ether.buffer[ETH_ARP_SRC_IP_P + i]    = ip[ether.select_ether][i];
      for (uint8_t i = 0; i < 6; i++)ether.buffer[ETH_ARP_SRC_MAC_P + i]   = mac[ether.select_ether][i];
      for (uint8_t i = 0; i < 6; i++)ether.buffer[ETH_ARP_DST_MAC_P + i] = 0x00;
      for (uint8_t i = 0; i < 4; i++)ether.buffer[ETH_ARP_DST_IP_P + i]    = dst_ip[i];
      ether.packetSend(60);
      uint8_t count = 3;
      while (1) {
        if (count <= 0)break;
        buffer_len = ether.packetReceive();//パケット受け取り
        if (buffer_len != 0) {
          check_protocol();
          if (protocol_type == ARP)
            if (ether.buffer[ETH_ARP_OPCODE_L_P] == ETH_ARP_OPCODE_REPLY_L_V) {
              uint8_t src_ip[4] = {}; uint8_t src_mac[6] = {};
              Serial.print("reply packet ");
              for (uint8_t i = 0; i < 4; i++) {
                arp_table[arp_table_len + i] = ether.buffer[ETH_ARP_SRC_IP_P + i];
                src_ip[i] = ether.buffer[ETH_ARP_SRC_IP_P + i];
              }
              for (uint8_t i = 0; i < 6; i++) {
                arp_table[arp_table_len + 4 + i] = ether.buffer[ETH_ARP_SRC_MAC_P + i];
                src_mac[i] = ether.buffer[ETH_ARP_SRC_MAC_P + i];
              }
              arp_table_len += 10;
              for (uint8_t i = 0; i < buffer2_len; i++)ether.buffer[i] = buffer2[i];
              for (uint8_t i = 0; i < 6; i++)ether.buffer[ETH_DST_MAC + i] = arp_table[4 + i];
              for (uint8_t i = 0; i < 6; i++)ether.buffer[ETH_SRC_MAC + i] = mac[ether.select_ether][i];
              ether.packetSend(buffer_len);
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
           if(routing_table[i+0] == ether.select_ether){
               routing
             }
           }

         }
    */
  }
}

void loop() {
  buffer_len = ether.packetReceive();//パケット受け取り
  if (buffer_len) {
    Serial.println(buffer_len);
    check_protocol(); //パケットを解析
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
    if (!is_me())other_data();
  }
  if (icmp_left[ether.select_ether] <= 0) {
    ether.change_selectPin();
  }
}
