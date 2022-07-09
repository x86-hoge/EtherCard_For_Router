
#include <ENCRoute.h>
#include <TimerOne.h>


//IPアドレス
static uint8_t ip[2][4]  = {
    { 192, 168, 1, 1},
     {192, 168, 2, 1}
}; 

//ネットワークアドレス
static uint8_t network[2][4]  = {
  {192, 168, 1, 0,}, 
  {192, 168, 2, 0}}; 

//サブネットマスク
static uint8_t subnet[2][4]  = {
  { 255, 255, 255, 0}, 
  {255, 255, 255, 0}
}; 

//MACアドレス
static uint8_t mac[2][6] = {
    {0x13, 0x45, 0x75, 0xF2, 0x1A, 0x1B}, 
    {0x12, 0x10, 0x39, 0x07, 0x11, 0x11}
};

//CSピン
static uint8_t csPin[MAX_CONNECT_ENC28J60] = {
  8,
  9
};

//解析したプロトコルの種類
static uint8_t protocol_type = 0;

//バッファ
uint8_t ENC28J60::buffer[BUFFER_SIZE_ENC28J60]; 

static uint16_t buffer_len;//バッファの長さ

static uint8_t icmp_left[MAX_CONNECT_ENC28J60] = {};

static uint8_t arp_left[MAX_CONNECT_ENC28J60]  = {};

const uint8_t led_r[] = {1, 0, 1, 0, 1, 0, 1, 0};

const uint8_t led_g[] = {1, 1, 0, 0, 1, 1, 0, 0};

const uint8_t led_b[] = {1, 1, 1, 1, 0, 0, 0, 0};

enum STATUS{
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
