/* packet_openhpsdr_u.h
 * Header file for the OpenHPSDR USB over IP protocol packet disassembly
 *
 * Version: 0.3.1
 * Author:  Matthew J Wolf, N4MTT
 * Date:    20-MAY-2019
 *
 * This file is part of the OpenHPSDR-USB Plug-in for Wireshark.
 * Matthew J. Wolf <matthew.wolf.hpsdr@speciosus.net>
 * Copyright 2017 Matthew J. Wolf
 *
 * The OpenHPSDR-USB Plug-in for Wireshark is free software: you can
 * redistribute it and/or modify it under the terms of the GNU
 * General Public License as published by the Free Software Foundation,
 * either version 2 of the License, or (at your option) any later version.
 *
 * The OpenHPSDR-USB Plug-in for Wireshark is distributed in the hope that
 * it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 * the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the OpenHPSDR-USB Plug-in for Wireshark.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#define HPSDR_U_PORT 1024

#define ZERO_MASK     0x00
#define BOOLEAN_MASK  0x08
#define ALL_BITS_MASK 0xFF
#define BIT12_MASK    0x0FFF
#define BIT16_MASK    0xFFFF
#define BIT24_MASK    0xFFFFFF

//GLOBAL FLAGS MASKS
#define GF_START_STOP_ST 0x01 //0b00000001
#define GF_IQ_STATE      0x02 //0b00000010
#define GF_WB_STATE      0x04 //0b00000100
#define GF_BW_IQ_ST_ST   0x07 //0b00000111

// START-STOP MASKS
#define TH_IQ              0x01 //0b00000001
#define TH_WIDE_BANDSCOPE  0x02 //0b00000010
#define TH_MASK            0x07 //0b00000011

//USB EP6 C0 MASKS
#define SDR_C0_PTT   0x01 //0b00000001
#define SDR_C0_DASH  0x02 //0b00000010
#define SDR_C0_DOT   0x04 //0b00000100
#define SDR_C0_TYPE   0xF8 //0b11111000
//#define SDR_C0_MASK  0b00000111

//USB EP6 C1 TYPE 0 MASKS
#define SDR_C1_OVER  0x01 //0b00000001
#define SDR_C1_I01   0x02 //0b00000010
#define SDR_C1_I02   0x04 //0b00000100
#define SDR_C1_I03   0x08 //0b00001000
#define SDR_C1_I04   0x10 //0b00010000
#define SDR_C1_PLL   0x20 //0b00100000
#define SDR_C1_FREQ  0x40 //0b01000000
#define SDR_C1_MASK  0x7F //0b01111111

//SB EP6 C1 TYPE 20 MASKS
#define SDR_OVER_MASK 0x01 //0b00000001
#define SDR_MER_MASK  0xFE //0b11111110

//USB EP2 C0 MASKS
#define HOST_C0_MOX  0x01 //0b00000001
#define HOST_C0_TYPE 0xFE //0b11111110

//USB EP2 TYPE 0 MASKS
#define HOST_C1_SPEED 0x03 //0b00000011
#define HOST_C1_10MHZ 0x0C //0b00001100
#define HOST_C1_122S  0x10 //0b00010000
#define HOST_C1_CONF  0x60 //0b01100000
#define HOST_C1_MICS  0x80 //0b10000000
#define HOST_C2_MODE  0x01 //0b00000001
#define HOST_C2_OC0   0x02 //0b00000010
#define HOST_C2_OC1   0x04 //0b00000100
#define HOST_C2_OC2   0x08 //0b00001000
#define HOST_C2_OC3   0x10 //0b00010000
#define HOST_C2_OC4   0x20 //0b00100000
#define HOST_C2_OC5   0x40 //0b01000000
#define HOST_C2_OC6   0x80 //0b10000000
#define HOST_C3_P_ATT 0x03 //0b00000011
#define HOST_C3_PREAM 0x04 //0b00000100
#define HOST_C3_IFDIT 0x08 //0b00001000
#define HOST_C3_IFRAD 0x10 //0b00010000
#define HOST_C3_P_ANT 0x60 //0b01100000
#define HOST_C3_P_OUT 0x80 //0b10000000
#define HOST_C4_P_T_R 0x03 //0b00000011
#define HOST_C4_DUP   0x04 //0b00000100
#define HOST_C4_RX_NU 0x38 //0b00111000
#define HOST_C4_T_ST  0x40 //0b01000000
#define HOST_C4_C_FEQ 0x80 //0b10000000


//USB EP2 TYPE 12 MASKS
#define HOST_C2_MIC_B 0x01 //0b00000001
#define HOST_C2_MIC_L 0x02 //0b00000010
#define HOST_C2_E_T_F 0x04 //0b00000100
#define HOST_C2_EN_TU 0x08 //0b00001000
#define HOST_C2_AU_TU 0x10 //0b00010000
#define HOST_C2_AL_AP 0x20 //0b00100000
#define HOST_C2_AP_MA 0x40 //0b01000000
#define HOST_C2_VNA   0x80 //0b10000000
#define HOST_C3_F_13  0x01 //0b00000001
#define HOST_C3_F_20  0x02 //0b00000010
#define HOST_C3_F_9_5 0x04 //0b00000100
#define HOST_C3_F_6_5 0x08 //0b00001000
#define HOST_C3_F_1_5 0x10 //0b00010000
#define HOST_C3_HPF_B 0x20 //0b00100000
#define HOST_C3_6M_B  0x40 //b01000000
#define HOST_C3_D_P_R 0x80 //0b10000000
#define HOST_C4_20_30 0x01 //0b00000001
#define HOST_C4_60_40 0x02 //0b00000010
#define HOST_C4_F_80  0x04 //0b00000100
#define HOST_C4_F_160 0x08 //0b00001000
#define HOST_C4_F_6   0x10 //0b00010000
#define HOST_C4_12_10 0x20 //0b00100000
#define HOST_C4_17_15 0x40 //0b01000000
#define HOST_C4_T_12  0x7F //0b01111111

//USB EP2 TYPE 14 MASKS
#define HOST_C1_2_14 0x7F //0b01111111
#define HOST_C1_RX1P 0x01 //0b00000001
#define HOST_C1_RX2P 0x02 //0b00000010
#define HOST_C1_RX3P 0x04 //0b00000100
#define HOST_C1_RX4P 0x08 //0b00001000
#define HOST_C1_O_TR 0x10 //0b00010000
#define HOST_C1_O_B  0x20 //0b00100000
#define HOST_C1_O_PT 0x40 //0b01000000
#define HOST_C2_TLV  0x1F //0b00011111
#define HOST_C2_A_TX 0x20 //0b00100000
#define HOST_C2_PURE 0x40 //0b01000000
#define HOST_C2_P_CW 0x80 //0b10000000
#define HOST_C3_2_14 0x1F //0b00011111
#define HOST_C3_M_P1 0x01 //0b00000001
#define HOST_C3_M_P2 0x02 //0b00000010
#define HOST_C3_M_P3 0x04 //0b00000100
#define HOST_C3_M_P4 0x08 //0b00001000
#define HOST_C3_A_TX 0x10 //0b00010000
#define HOST_C4_2_14 0x3F //0b00111111
#define HOST_C4_A1_A 0x1F //0b00011111
#define HOST_C4_HA_A 0x20 //0b00100000

//USB EP2 TYPE 16 MASKS
#define HOST_C1_2_16  0x3F //0b00111111
#define HOST_2_16_ADC 0x1F //0b00011111
#define HOST_2_16_AS  0x20 //0b00100000
#define HOST_C2_2_16  0x7F //00b01111111
#define HOST_C2_CW_R  0x40 //0b01000000
#define HOST_C3_CW_S  0x3F //0b00111111
#define HOST_C3_CW_KM 0xC0 //0b11000000
#define HOST_C4_CW_KW 0x7F //0b01111111
#define HOST_C4_CW_KS 0x80 //0b10000000

//USB EP2 TYPE 1C MASKS
#define HOST_C1_R1_AD 0x03 //0b00000011
#define HOST_C1_R2_AD 0x0C //0b00001100
#define HOST_C1_R3_AD 0x30 //0b00110000
#define HOST_C1_R4_AD 0xC0 //0b11000000
#define HOST_C2_2_1E  0x3F //0b00111111
#define HOST_C2_R5_AD 0x03 //0b00000011
#define HOST_C2_R6_AD 0x0C //0b00001100
#define HOST_C2_R7_AD 0x30 //0b00110000
#define HOST_C3_A_I_A 0x1F //0b00011111

//USB EP2 TYPE 1E MASKS
#define HOST_C1_CW_SO 0x01 //0b00000001

//USB EP2 TYPE 20 MASKS
#define HOST_2_20_CW_H 0x03FF //0b0000001111111111
#define HOST_2_20_CW_F 0x0FFF //0b0000111111111111

//USB EP2 TYPE 22 MASKS
#define HOST_2_22 0x03FF //0b0000001111111111

void proto_register_hpsdr_u(void);

static int hpsdr_usb_ep2_frame(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int frame_num);
static int hpsdr_usb_ep6_frame(proto_tree *tree, tvbuff_t *tvb, int offset, int frame_num);

static void dissect_hpsdr_u(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void proto_reg_handoff_hpsdr_u(void);
