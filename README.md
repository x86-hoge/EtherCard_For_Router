# EtherCard_For_Router

**EtherCard_For_Router** はEtherCardをRouter作成用に改造したENC28J60ドライバ

* フォーク元 EtherCard
* ライセンス GPL2

## 対応ハードウェアについて
    * Arduino Uno　※対応確認済
    * Arduino Mega　※未確認
    * Arduino Leonardo　※未確認



## Physical Installation

### ピン接続 (Using Arduino UNO or Arduino NANO):

| ENC28J60 | Arduino Uno | Notes                                       |
|----------|-------------|---------------------------------------------|
| VCC      | 3.3V        |                                             |
| GND      | GND         |                                             |
| SCK      | Pin 13      |                                             |
| MISO     | Pin 12      |                                             |
| MOSI     | Pin 11      |                                             |
| CS       | Pin 10      | Selectable with the ether.begin() function  |


### ピン接続(Arduino Mega)

| ENC28J60 | Arduino Mega | Notes                                       |
|----------|--------------|---------------------------------------------|
| VCC      | 3.3V         |                                             |
| GND      | GND          |                                             |
| SCK      | Pin 52       |                                             |
| MISO     | Pin 50       |                                             |
| MOSI     | Pin 51       |                                             |
| CS       | Pin 53       | Selectable with the ether.begin() function  |