/*
*/
#ifndef ENCRoute_h
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

#define BUFFER_SIZE_ENC28J60 1000



class ENCRoute: public ENC28J60{
    public:
        /**/
        static uint8_t ip[MAX_CONNECT_ENC28J60][IP_LEN];
        static uint8_t network[MAX_CONNECT_ENC28J60][IP_LEN];
        static uint8_t subnet[MAX_CONNECT_ENC28J60][IP_LEN];
        static uint8_t mac[MAX_CONNECT_ENC28J60][MAC_LEN];
        static uint8_t csPin[MAX_CONNECT_ENC28J60];
        static uint8_t arp_table[100];
        static uint8_t arp_table_len;
        static uint8_t routing_table[60];
        static uint8_t routing_table_len;
        static uint8_t protocol_type;

        /* L2タイプフィールドをチェックし変数に格納 */
        static void checkProtocol();
        /* ルータ宛のARPリクエストの返信 */
        static void Rep_Arp();
        /* ARPパケットを作成し、返信が来るまで待機 */
        static void Req_Arp();
        /* チェックサムを算出 */
        static uint16_t checksum(uint8_t addr,uint16_t len);

        /* 自分宛てのパケットか確認 */
        static bool isMe();
        
        static void check_arp();
        /* ルータ宛のARPリクエストの返信 */
        static void rep_icmp();
        /* TCPプロトコルをチェックし格納（開発中） */
        static void check_tcp();
        /* ルーティング */
        static void transferData();
        /* DHCP機能（開発中） */
        static void checkDHCP();
        /* 光 */
        static void lightProtocol();
        /* 処理開始 */
        static void start();

        /* デバック用 */
        static void show_mac(uint8_t* mac);
        static void show_ip(uint8_t* ip);
        static void show_test();
};


extern ENCRoute router;

#endif