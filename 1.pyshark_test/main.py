import pyshark

def detect_avrcp_pause(file_path):
    # Wiresharkキャプチャファイルを読み込む
    cap = pyshark.FileCapture(file_path, display_filter='bluetooth')
    # 各パケットを検査
    for i,packet in enumerate(cap):
        # if 'HCI_H4' in packet:
        #     print(packet['HCI_H4'])
        try:
            if 'BTAVRCP' in packet:
                avrcp_packet = packet['BTAVRCP']
                # Ctype = 0x00はControl
                if avrcp_packet.get_field_value('Ctype') == '0x00':
                    print('Ctype is Control')
                    if avrcp_packet.get_field_value('Opcode') and avrcp_packet.get_field_value('Opcode') == '0x00':
                        print('opcode is Vender dependent')
                    if avrcp_packet.get_field_value('Opcode') and avrcp_packet.get_field_value('Opcode') == '0x7c':
                        print('Opcode is Pass Through')
                        print('state:' + str(avrcp_packet.get_field_value('State')))
                        if avrcp_packet.get_field_value('Operation ID') and avrcp_packet.get_field_value('Operation ID') == '0x46':
                            print('opration ID is PAUSE(0x46)')
            else:
                continue
        except AttributeError:
            # 必要な属性がパケットにない場合
            continue

# Wiresharkキャプチャファイルのパス
file_path = 'btsnoop_hci.log'

# AVRCP Pause要求の検出関数を実行
detect_avrcp_pause(file_path)
