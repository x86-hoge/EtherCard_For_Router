#ifndef  ENCRoute_h
#define ENCRoute_h

#if ARDUINO >= 100
#include <Arduino.h> // Arduino 1.0
#define WRITE_RESULT size_t
#define WRITE_RETURN return 1;
#else
#include <WProgram.h> // Arduino 0022
#define WRITE_RESULT void
#define WRITE_RETURN
#endif

#include <avr/pgmspace.h>

#include "enc28j60.h"
#include "net.h"
#include "enc_config.h"
/*
class ENCROUTE: public ENC28J60{
    public:
        static uint8_t Ip_Table[][];
        static uint8_t Subnet_Table[][];
        static uint8_t Mac_Table[][];
        static uint8_t csPins[];
        static uint8_t Arp_Table[];
        static uint8_t Arp_Table_Len;
        static uint8_t Routing_Table[];
        static uint8_t Routing_Table_Len[];
        static uint16_t buffer_len;
        //L2タイプフィールドをチェックし変数に格納
        static void Check_Protocol();
        //ルータ宛のARPリクエストの返信
        static void Rep_Arp();
        //ARPパケットを作成し、返信が来るまで待つ
        static void Req_Arp();
        //チェックサムを算出する
        static void CheckSum(uint8_t addr,uint16_t len);
        //自分宛てのパケットか確認
        static bool is_Dst_Me();
        //ルータ宛のARPリクエストの返信
        static void Rep_Icmp();
        //TCPプロトコルをチェックし格納（開発中）
        static void Check_Tcp();
        //ルーティング
        static void Other_Data();
        //DHCP機能（開発中）
        static void Check_DHCP();
}
*/

extern ENC28J60 ether;

#endif