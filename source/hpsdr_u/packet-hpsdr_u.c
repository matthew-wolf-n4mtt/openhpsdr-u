/* packet-hpsdr_u.c  
 * Routines for the HPSDR USB over IP protocol packet disassembly
 *
 * This file is part of the HPSDR-USB Plug-in for Wireshark.
 * By Matthew J. Wolf <matthew.wolf.hpsdr@speciosus.net>
 * Copyright 2017 Matthew J. Wolf
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * PowerSDR is a C# implementation of a Software Defined Radio.
 * Copyright (C) 2004-2009  FlexRadio Systems 
 * Copyright (C) 2010-2015  Doug Wigley
 *
 * The HPSDR-USB Plug-in for Wireshark is free software: you can 
 * redistribute it and/or modify it under the terms of the GNU 
 * General Public License as published by the Free Software Foundation,
 * either version 2 of the License, or (at your option) any later version.
 * 
 * The HPSDR-USB Plug-in for Wireshark is distributed in the hope that
 * it will be useful, but WITHOUT ANY WARRANTY; without even the implied 
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See 
 * the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the HPSDR-USB Plug-in for Wireshark.  
 * If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * The HPSDR-USB Plug-in for Wireshark is written to disassemble the protocol
 * that is defined in the documents listed below.
 * 
 * Metis - How it Works_V1.33: 28-Feb-2015
 * http://svn.tapr.org/repos_sdr_hpsdr/trunk/Metis/Documentation/Metis-%20How%20it%20works_V1.33.pdf  
 *
 * HPSDR - USB Data Protocol, Version 1.58: 4-Aug-2014
 * http://svn.tapr.org/repos_sdr_hpsdr/trunk/Documentation/USB_protocol_V1.58.doc
 *
 */
#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "packet-hpsdr_u.h"

//Port definition in hpsdr_u.h header

/* subtree state variables */
static gint ett_hpsdr_u = -1;
static gint ett_hpsdr_u_f1 = -1;
static gint ett_hpsdr_u_f2 = -1;
static gint ett_hpsdr_u_c0 = -1;
static gint ett_hpsdr_u_cc_conf = -1;
static gint ett_hpsdr_u_cc_filter = -1;
static gint ett_hpsdr_u_cc_misc = -1;
static gint ett_hpsdr_u_cc_adc_cw = -1;
static gint ett_hpsdr_u_cc_rx_adc = -1;
static gint ett_hpsdr_u_cc_cw1 = -1;
static gint ett_hpsdr_u_cc_cw2 = -1;
static gint ett_hpsdr_u_cc_pwm = -1;
static gint ett_hpsdr_u_ep2_data_1 = -1;
static gint ett_hpsdr_u_ep2_data_2 = -1;
static gint ett_hpsdr_u_cc_info = -1;
static gint ett_hpsdr_u_cc_fp = -1;
static gint ett_hpsdr_u_cc_rp = -1;
static gint ett_hpsdr_u_cc_ps = -1;
static gint ett_hpsdr_u_cc_ov = -1;
static gint ett_hpsdr_u_ep6_data_1 = -1;
static gint ett_hpsdr_u_ep6_data_2 = -1;

/* protocol variables */
static int proto_hpsdr_u = -1;

/* fields */ 
static int hf_hpsdr_u_ei = -1;
static int hf_hpsdr_u_id = -1;
static int hf_hpsdr_u_status = -1;
static int hf_hpsdr_u_eth = -1;
static int hf_hpsdr_u_ver =-1;
static int hf_hpsdr_u_bid = -1;
static int hf_hpsdr_u_hlite_ver = -1;
static int hf_hpsdr_u_host_discover = -1;
static int hf_hpsdr_u_end_point = -1;
static int hf_hpsdr_u_seq = -1;
static int hf_hpsdr_u_setip_mac = -1;
static int hf_hpsdr_u_setip_address = -1;
static int hf_hpsdr_u_pad = -1;
static int hf_hpsdr_u_com_iq = -1;
static int hf_hpsdr_u_com_wb = -1;
static int hf_hpsdr_u_sync_1 = -1;
static int hf_hpsdr_u_sync_2 = -1;
static int hf_hpsdr_u_ep_f1 = -1;
static int hf_hpsdr_u_ep_f2 = -1;
static int hf_hpsdr_u_c0_1 = -1;
static int hf_hpsdr_u_c0_2 = -1;
static int hf_hpsdr_u_c0_sub_1 = -1;
static int hf_hpsdr_u_c0_sub_2 = -1;
static int hf_hpsdr_u_c0_ptt_1 = -1;
static int hf_hpsdr_u_c0_ptt_2 = -1;
static int hf_hpsdr_u_c0_dash_1 = -1;
static int hf_hpsdr_u_c0_dash_2 = -1;
static int hf_hpsdr_u_c0_dot_1 = -1;
static int hf_hpsdr_u_c0_dot_2 = -1;
static int hf_hpsdr_u_c0_type_1 = -1;
static int hf_hpsdr_u_c0_type_2 = -1;
static int hf_hpsdr_u_cc_info_sub = -1;
static int hf_hpsdr_u_cc_info_c1 = -1;
static int hf_hpsdr_u_cc_info_adc_overflow = -1;
static int hf_hpsdr_u_cc_info_i01 = -1;
static int hf_hpsdr_u_cc_info_i02 = -1;
static int hf_hpsdr_u_cc_info_i03 = -1;
static int hf_hpsdr_u_cc_info_i04 = -1;
static int hf_hpsdr_u_cc_info_cyclops_pll =-1;
static int hf_hpsdr_u_cc_info_freq_chg = -1;
static int hf_hpsdr_u_cc_info_mercury =-1;
static int hf_hpsdr_u_cc_info_penelope = -1; 
static int hf_hpsdr_u_cc_info_interface = -1; 
static int hf_hpsdr_u_cc_fwdpw_sub = -1;
static int hf_hpsdr_u_cc_fwdpw_tx = -1;
static int hf_hpsdr_u_cc_fwdpw_ant_pre = -1;
static int hf_hpsdr_u_cc_revpwd_sub = -1;
static int hf_hpsdr_u_cc_revpwd_rev = -1;
static int hf_hpsdr_u_cc_revpwd_ain3 = -1;
static int hf_hpsdr_u_cc_pwsupp_sub =- 1;
static int hf_hpsdr_u_cc_pwsupp_ain4 = -1;
static int hf_hpsdr_u_cc_pwsupp_vol = -1;
static int hf_hpsdr_u_cc_overflow_sub =- 1;
static int hf_hpsdr_u_cc_overflow_mercury1 = -1;
static int hf_hpsdr_u_cc_overflow_adc1 = -1;
static int hf_hpsdr_u_cc_overflow_mercury2 = -1;
static int hf_hpsdr_u_cc_overflow_adc2 = -1;
static int hf_hpsdr_u_cc_overflow_mercury3 = -1;
static int hf_hpsdr_u_cc_overflow_adc3 = -1;
static int hf_hpsdr_u_cc_overflow_mercury4 = -1;
static int hf_hpsdr_u_cc_overflow_adc4 = -1;
static int hf_hpsdr_u_ep6_num_of_rx_1 =-1;
static int hf_hpsdr_u_ep6_num_of_rx_2 =-1;
static int hf_hpsdr_u_ep6_data_1 = -1;
static int hf_hpsdr_u_ep6_data_2 = -1;
static int hf_hpsdr_u_c0_mox_1 = -1;
static int hf_hpsdr_u_c0_mox_2 = -1;
static int hf_hpsdr_u_ep2_c0_type_1 = -1;
static int hf_hpsdr_u_ep2_c0_type_2 = -1;
static int hf_hpsdr_u_ep2_data_1 = -1;
static int hf_hpsdr_u_ep2_data_2 = -1;
static int hf_hpsdr_u_cc_conf_c1_1 = -1;
static int hf_hpsdr_u_cc_conf_c2_1 = -1;
static int hf_hpsdr_u_cc_conf_c3_1 = -1;
static int hf_hpsdr_u_cc_conf_c4_1 = -1;
static int hf_hpsdr_u_cc_conf_sub_1 = -1;
static int hf_hpsdr_u_cc_conf_c1_2 = -1;
static int hf_hpsdr_u_cc_conf_c2_2 = -1;
static int hf_hpsdr_u_cc_conf_c3_2 = -1;
static int hf_hpsdr_u_cc_conf_c4_2 = -1;
static int hf_hpsdr_u_cc_conf_sub_2 = -1;
static int hf_hpsdr_u_cc_speed = -1;
static int hf_hpsdr_u_cc_10mhz = -1;
static int hf_hpsdr_u_cc_122mhz = -1;
static int hf_hpsdr_u_cc_conf = -1;
static int hf_hpsdr_u_cc_mic_s = -1;
static int hf_hpsdr_u_cc_mode = -1;
static int hf_hpsdr_u_cc_oco_0 = -1;
static int hf_hpsdr_u_cc_oco_1 = -1;
static int hf_hpsdr_u_cc_oco_2 = -1;
static int hf_hpsdr_u_cc_oco_3 = -1;
static int hf_hpsdr_u_cc_oco_4 = -1;
static int hf_hpsdr_u_cc_oco_5 = -1;
static int hf_hpsdr_u_cc_oco_6 = -1;
static int hf_hpsdr_u_cc_ant_pre_attn = -1;
static int hf_hpsdr_u_cc_ant_pre_pre_amp = -1;
static int hf_hpsdr_u_cc_adc_dither = -1;
static int hf_hpsdr_u_cc_adc_random = -1;
static int hf_hpsdr_u_cc_ant_pre_ant = -1;
static int hf_hpsdr_u_cc_ant_pre_rx_out = -1;
static int hf_hpsdr_u_cc_ant_pre_tx_relay = -1;
static int hf_hpsdr_u_cc_dup = -1;
static int hf_hpsdr_u_cc_rx_num = -1;
static int hf_hpsdr_u_cc_mic_ts = -1;
static int hf_hpsdr_u_cc_com_merc_freq = -1;
static int hf_hpsdr_u_cc_nco_tx = -1;
static int hf_hpsdr_u_cc_nco_rx_1 = -1;
static int hf_hpsdr_u_cc_nco_rx_2 = -1;
static int hf_hpsdr_u_cc_nco_rx_3 = -1;
static int hf_hpsdr_u_cc_nco_rx_4 = -1;
static int hf_hpsdr_u_cc_nco_rx_5 = -1;
static int hf_hpsdr_u_cc_nco_rx_6 = -1;
static int hf_hpsdr_u_cc_nco_rx_7 = -1;
static int hf_hpsdr_u_cc_tx_drive = -1;
static int hf_hpsdr_u_cc_filter_sub = -1;
static int hf_hpsdr_u_cc_mic_boost = -1;
static int hf_hpsdr_u_cc_mic_l = -1;
static int hf_hpsdr_u_cc_apollo_filter = -1;
static int hf_hpsdr_u_cc_apollo_tunner = -1;
static int hf_hpsdr_u_cc_apollo_auto = -1;
static int hf_hpsdr_u_cc_herm_fil_s = -1;
static int hf_hpsdr_u_cc_filter_man = -1;
static int hf_hpsdr_u_cc_vna = -1;
static int hf_hpsdr_u_cc_hpf_13 = -1;
static int hf_hpsdr_u_cc_hpf_20 = -1;
static int hf_hpsdr_u_cc_hpf_9_5 = -1;
static int hf_hpsdr_u_cc_hpf_6_5 = -1;
static int hf_hpsdr_u_cc_hpf_1_5 = -1;
static int hf_hpsdr_u_cc_bypass_hpf = -1;
static int hf_hpsdr_u_cc_6m_amp = -1;
static int hf_hpsdr_u_cc_dis_ant_pre_tr = -1;
static int hf_hpsdr_u_cc_ep2_c4_12 =-1;
static int hf_hpsdr_u_cc_lpf_30_20 = -1;
static int hf_hpsdr_u_cc_lpf_60_40 = -1;
static int hf_hpsdr_u_cc_lpf_80 = -1;
static int hf_hpsdr_u_cc_lpf_160 = -1;
static int hf_hpsdr_u_cc_lpf_6 = -1;
static int hf_hpsdr_u_cc_lpf_12_10 = -1;
static int hf_hpsdr_u_cc_lpf_17_15 = -1;
static int hf_hpsdr_u_cc_ep2_c1_14 = -1;
static int hf_hpsdr_u_cc_rx1_preamp = -1;
static int hf_hpsdr_u_cc_rx2_preamp = -1;
static int hf_hpsdr_u_cc_rx3_preamp = -1;
static int hf_hpsdr_u_cc_rx4_preamp = -1;
static int hf_hpsdr_u_cc_orion_mic_tr = -1;
static int hf_hpsdr_u_cc_orion_mic_bias = -1;
static int hf_hpsdr_u_cc_orion_mic_ptt = -1;
static int hf_hpsdr_u_cc_codec_line_gain = -1;
static int hf_hpsdr_u_cc_merc_tx_atten_c2 = -1;
static int hf_hpsdr_u_cc_pure_signal = -1;
static int hf_hpsdr_u_cc_penelope_cw = -1;
static int hf_hpsdr_u_cc_ep2_c3_14 = -1;
static int hf_hpsdr_u_cc_metis_p1 = -1;
static int hf_hpsdr_u_cc_metis_p2 = -1;
static int hf_hpsdr_u_cc_metis_p3 = -1;
static int hf_hpsdr_u_cc_metis_p4 = -1;
static int hf_hpsdr_u_cc_ep2_c4_14 = -1;
static int hf_hpsdr_u_cc_merc_tx_atten_c3 = -1;
static int hf_hpsdr_u_cc_adc1_rx_atten = -1;
static int hf_hpsdr_u_cc_herm_angelia_atten = -1;
static int hf_hpsdr_u_cc_ep2_c1_16 = -1;
static int hf_hpsdr_u_cc_adc2_rx_atten = -1;
static int hf_hpsdr_u_cc_adc2_en = -1;
static int hf_hpsdr_u_cc_ep2_c2_16 = -1;
static int hf_hpsdr_u_cc_adc3_rx_atten = -1;
static int hf_hpsdr_u_cc_adc3_en = -1;
static int hf_hpsdr_u_cc_cw_rev = -1;
static int hf_hpsdr_u_cc_cw_keyer_speed = -1;
static int hf_hpsdr_u_cc_cw_keyer_mode = -1;
static int hf_hpsdr_u_cc_cw_keyer_weight = -1;
static int hf_hpsdr_u_cc_cw_keyer_spacing = -1;
static int hf_hpsdr_u_cc_rx1_adc_assign = -1;
static int hf_hpsdr_u_cc_rx2_adc_assign = -1;
static int hf_hpsdr_u_cc_rx3_adc_assign = -1;
static int hf_hpsdr_u_cc_rx4_adc_assign = -1;
static int hf_hpsdr_u_cc_ep2_c2_1c = -1;
static int hf_hpsdr_u_cc_rx5_adc_assign = -1;
static int hf_hpsdr_u_cc_rx6_adc_assign = -1;
static int hf_hpsdr_u_cc_rx7_adc_assign = -1;
static int hf_hpsdr_u_cc_adc_input_atten_tx = -1;
static int hf_hpsdr_u_cc_cw_source = -1;
static int hf_hpsdr_u_cc_cw_sidetone_vol = -1;
static int hf_hpsdr_u_cc_cw_ptt_delay = -1;
static int hf_hpsdr_u_cc_cw_hang_time = -1;
static int hf_hpsdr_u_cc_cw_sidetone_freq = -1;
static int hf_hpsdr_u_cc_pwm_min = -1;
static int hf_hpsdr_u_cc_pwm_max = -1;
static int hf_hpsdr_u_ep2_data_sub_1 = -1;
static int hf_hpsdr_u_ep2_data_sub_2 = -1;
static int hf_hpsdr_u_ep2_idx = -1;
static int hf_hpsdr_u_ep2_l = -1;
static int hf_hpsdr_u_ep2_r = -1;
static int hf_hpsdr_u_ep2_i = -1;
static int hf_hpsdr_u_ep2_q = -1;
static int hf_hpsdr_u_ep4_separator = -1;
static int hf_hpsdr_u_ep4_sample_idx  = -1;
static int hf_hpsdr_u_ep4_sample = -1;
static int hf_hpsdr_u_ep6_data_sub_1 = -1;
static int hf_hpsdr_u_ep6_data_sub_2 = -1;
static int hf_hpsdr_u_ep6_idx = -1;
static int hf_hpsdr_u_ep6_rx_idx = -1;
static int hf_hpsdr_u_ep6_i = -1;
static int hf_hpsdr_u_ep6_q = -1;
static int hf_hpsdr_u_ep6_data_string_ml = -1;
static int hf_hpsdr_u_ep6_ml = -1;
static int hf_hpsdr_u_ep6_data_string_end = -1;
static int hf_hpsdr_u_ep6_data_pad = -1;

// Expert Items
static expert_field ei_ep2_sync = EI_INIT;
static expert_field ei_extra_length = EI_INIT;

// Preferences
static gboolean hpsdr_u_strict_size = TRUE;
static gboolean hpsdr_u_strict_pad = TRUE;
static gboolean hpsdr_u_ep2_sync = TRUE;

static guint8 board_id = -1;

static int rx_num = 0;       // Number of Recevers
                             // Inital value of 0 until the real number is discovered.

static int global_flags = 0; // Inital state is all stoped, aka 0 


static const value_string hpsdr_u_status_types[] = {
    { 0x01, "Data TX" },
    { 0x02, "Discovery" },
    { 0x03, "Set IP Address - Program" },  //NOT Included!
    { 0x04, "Start - Stop" },
    {0, NULL}
};

static const value_string hpsdr_u_ids[] = {
    { 0x00, "Metis" },
    { 0x01, "Hermes" },
    { 0x02, "Griffin" },
    { 0x04, "Angelia" },
    { 0x05, "Orion" },
    { 0x06, "Hermes_Lite" },
    {0, NULL}
};

static const value_string hpsdr_u_end_points_types[] = {
    { 0x02, "USB EP2 - Host to SDR" },
    { 0x04, "USB EP4 - SDR to Host: Raw ADC Samples" },   //NOT Included!
    { 0x06, "USB EP6 - SDR to Host: C&C, IQ, Mic/Line Samples" },
    {0, NULL}
};

static const value_string ep2_speed[] = {
    { 0x00, "48kHz" },  // 0b00
    { 0x01, "96kHz" },  // 0b01
    { 0x02, "192kHz" }, // 0b10
    { 0x03, "384kHz" }, // 0b11
    {0, NULL}
};

static const value_string ep2_10mhz[] = {
    { 0x00, "Atlas / Excalibur" },
    { 0x01, "Penelope" },
    { 0x02, "Mercury" },
    {0, NULL}
};

static const value_string ep2_config[] = {
    { 0x00, "nil" },
    { 0x01, "Penelope" },
    { 0x02, "Mercury" },
    { 0x03, "Penelope and Mercury" },
    {0, NULL}
};


static const value_string ep2_pre_attn[] = {
    { 0x00, "0dB" },
    { 0x01, "10dB" },
    { 0x02, "20dB" },
    { 0x03, "30dB" },
    {0, NULL}
};

static const value_string ep2_pre_rx_ant[] = {
    { 0x00, "None" },
    { 0x01, "RX 1" },
    { 0x02, "RX 2" },
    { 0x03, "XV" },
    {0, NULL}
};

static const value_string ep2_pre_tx_relay[] = {
    { 0x00, "TX 1" },
    { 0x01, "TX 2" },
    { 0x02, "TX 3" },
    {0, NULL}
};

static const value_string ep2_cw_mode[] = {
    { 0x00, "Straight" },
    { 0x01, "Mode A" },
    { 0x02, "Mode B" },
    {0, NULL}
};

static const value_string ep2_adc_asign[] = {
    { 0x00, "ADC 1" },
    { 0x01, "ADC 2" },
    { 0x10, "ADC 3" },
    {0, NULL}
};


static const true_false_string start_stop = {
    "Start",
    "Stop"
};

static const true_false_string blank_blank = {
    "",
    ""
};

static const  true_false_string inactive_active = {
    "Inactive",    // when true  (1)
    "Active"       // when false (0)
};

static const true_false_string lock_unlock = {
    "Locked",
    "Unlocked"
};

static const true_false_string mercury_penelope = {
    "Mercury",
    "Penelope"
};

static const true_false_string penelope_janus = {
    "Penelope",
    "Janus"
};

static const true_false_string ClassE_other = {
    "Class E",
    "Other Mode"
};

static const true_false_string same_independent = {
    "Same",
    "Independent"
};

static const true_false_string zero_20 = {
    "20dB",
    "0db"
};

static const true_false_string line_mic = {
    "Line-In",
    "Mic"
};

static const true_false_string start_end = {
    "Start",
    "End"
};

static const true_false_string apollo_alex = {
    "Apollo",
    "Alex"
};

static const true_false_string tip_ring = {
    "micPTT to Tip, Mic/Mic Bias to Ring",
    "micPTT to Ring, Mic/Mic Bias to Tip"
};

static const true_false_string ha_a_enabled_disabled = {
    "Enabled",
    "Disabled - Preamp On/Off Bit is Used"
};

static const true_false_string adc_enabled_disabled = {
    "Enabled",
    "Disabled - Attenuation is 0dB"
};

static const true_false_string internal_external = {
    "Internal",
    "External"
};


// The Windows build env does not like to pull in stuff
// from other DLL. The next five true_false_strings duplicate
// strings that are inculded in the wireshark tfs.h source.
const true_false_string local_active_inactive = { "Active", "Inactive" };
const true_false_string local_set_notset = { "Set", "Not set" };
const true_false_string local_on_off = { "On", "Off" };
const true_false_string local_enabled_disabled = { "Enabled", "Disabled" };
const true_false_string local_disabled_enabled = { "Disabled", "Enabled" };

void 
proto_register_hpsdr_u(void)
{
   module_t *hpsdr_u_prefs;
   expert_module_t *expert_hpsdr_u;

   static hf_register_info hf[] = {
       { &hf_hpsdr_u_ei,
           { "CR Expert" , "openhpsdr-e.cr.ei",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_id,
           { "ID" , "hpsdr-u.id",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_status,
           { "Status" , "hpsdr-u.status",
            FT_UINT8, BASE_HEX,
            VALS(hpsdr_u_status_types), ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_eth,
           { "SDR MAC Address " , "hpsdr-u.eth",
            FT_ETHER, BASE_NONE,
            NULL, ZERO_MASK,
            "Hardware Address", HFILL }
       },
       { &hf_hpsdr_u_ver,
           { "SDR Code Version" , "hpsdr-u.ver",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_bid,
           { "SDR Board ID    " , "hpsdr-u.bid",
            FT_UINT8, BASE_HEX,
            VALS(hpsdr_u_ids), ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_hlite_ver,
           { "Hermes Light Version" , "hpsdr-u.hlv",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_host_discover,
           { "Host Discovery string" , "hpsdr-u.hdis",
            FT_STRING , BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_end_point,
           { "USB End Point  " , "hpsdr-u.ep",
            FT_UINT8, BASE_HEX,
            VALS(hpsdr_u_end_points_types), ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_seq,
           { "Sequence Number" , "hpsdr-u.seq",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_setip_mac,
	   { "MAC Address" , "hpsdr-u.setip-mac",
            FT_ETHER, BASE_NONE,
            NULL, ZERO_MASK,
            "Hardware Address", HFILL }
       },
       { &hf_hpsdr_u_setip_address,
           { "IP Address " , "hpsdr-u.setip-address",
            FT_IPv4, BASE_NETMASK,
            NULL, ZERO_MASK,
            "Hardware Address", HFILL }
       },
       { &hf_hpsdr_u_pad,
           { "Zero Pad" , "hpsdr-u.pad",
            FT_STRING, BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_com_iq,
           { "IQ & MIC Data " , "hpsdr-u.com.start-stop.iq",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&start_stop), TH_IQ,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_com_wb,
           { "Wide Bandscope" , "hpsdr-u.com.start-stop.wb",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&start_stop), TH_WIDE_BANDSCOPE,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_sync_1,
           { "Sync        " , "hpsdr-u.sync_1",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_sync_2,
           { "Sync        " , "hpsdr-u.sync_2",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep_f1,
           { "USB EP Frame 1 Submenu" , "hpsdr-u.ep6.f1-sub",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep_f2,
           { "USB EP Frame 2 Submenu" , "hpsdr-u.ep6.f2-sub",
            FT_UINT8, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_c0_1,
           { "C&C Byte 0" , "hpsdr-u.cc0_1",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_c0_2,
           { "C&C Byte 0" , "hpsdr-u.cc0_2",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_c0_sub_1,
           { "C0 SubMenu" , "hpsdr-u.cc0.sub_1",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_c0_sub_2,
           { "C0 SubMenu" , "hpsdr-u.cc0.sub_2",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_c0_ptt_1,
           { "    PTT" , "hpsdr-u.cc0.ptt_1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_active_inactive), SDR_C0_PTT,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_c0_ptt_2,
           { "    PTT" , "hpsdr-u.cc0.ptt_2",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_active_inactive), SDR_C0_PTT,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_c0_dash_1,
           { "   DASH" , "hpsdr-u.cc0.dash_1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_active_inactive), SDR_C0_DASH,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_c0_dash_2,
           { "   DASH" , "hpsdr-u.cc0.dash_2",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_active_inactive), SDR_C0_DASH,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_c0_dot_1,
           { "    DOT" , "hpsdr-u.cc0.dot_1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_active_inactive), SDR_C0_DOT,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_c0_dot_2,
           { "    DOT" , "hpsdr-u.cc0.dot_2",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_active_inactive), SDR_C0_DOT,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_c0_type_1,
           { "C0 Type" , "hpsdr-u.cc0.type_1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&blank_blank), SDR_C0_TYPE,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_c0_type_2,
           { "C0 Type" , "hpsdr-u.cc0.type_2",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&blank_blank), SDR_C0_TYPE,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_fwdpw_sub,
           { "Forward Power subtree" , "hpsdr-u.cc.fwdpw.sub",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_fwdpw_tx,
           { "SDR Forward TX Power (AIN5)" , "hpsdr-u.cc.fwdpw.tx",
            FT_UINT16, BASE_HEX,
            NULL, BIT12_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_fwdpw_ant_pre,
           { "SDR TX Forward Power From Anntena Preselector (AIN1)" , "hpsdr-u.cc.fwdpw.ant-pre",
            FT_UINT16, BASE_HEX,
            NULL, BIT12_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_revpwd_sub,
           { "Reverse Power subtree" , "hpsdr-u.cc.revpwd.sub",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_revpwd_rev,
           { "SDR Reverse Power From Anntena Preselector (AIN2)    " , "hpsdr-u.cc.revpwd.ant-pre-rev",
            FT_UINT16, BASE_HEX,
            NULL, BIT12_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_revpwd_ain3,
           { "SDR AIN3 Value                                       " , "hpsdr-u.cc.revpwd.ain3",
            FT_UINT16, BASE_HEX,
            NULL, BIT12_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_info_sub,
           { "Info subtree" , "hpsdr-u.cc.info.sub",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_info_c1,
           { "C&C Byte 1" , "hpsdr-u.cc.info.c1",
            FT_UINT8, BASE_HEX,
            NULL, SDR_C1_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_info_adc_overflow,
           { "ADC Overflow" , "hpsdr-u.cc.info.adc-overflow",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_active_inactive), SDR_C1_OVER,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_info_i01,
           { "  Hermes I01" , "hpsdr-u.cc.info.i01",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&inactive_active), SDR_C1_I01,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_info_i02,
           { "  Hermes I02" , "hpsdr-u.cc.info.i02",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&inactive_active), SDR_C1_I02,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_info_i03,
           { "  Hermes I03" , "hpsdr-u.cc.info.i03",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&inactive_active), SDR_C1_I03,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_info_i04,
           { "  Hermes I04" , "hpsdr-u.cc.info.i04",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&inactive_active), SDR_C1_I04,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_info_cyclops_pll,
           { " Cyclops PLL" , "hpsdr-u.cc.info.cyclops-pll",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&lock_unlock), SDR_C1_PLL,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_info_freq_chg,
           { "SDR Frequency changed" , "hpsdr-u.cc.info.freq-chg",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_set_notset), SDR_C1_FREQ,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_info_mercury,
           { "Mercury Software Version " , "hpsdr-u.cc.info.mercury",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_info_penelope,
           { "Penelope Software Version" , "hpsdr-u.cc.info.penelope",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_info_interface,
           { "Interface Device Software Version" , "hpsdr-u.cc.info.interface",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_pwsupp_sub,
           { "Power Supply Report subtree" , "hpsdr-u.cc.pwsupp.sub",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_pwsupp_ain4,
           { "               SDR AIN4 Value" , "hpsdr-u.cc.pwsupp.ain4",
            FT_UINT16, BASE_HEX,
            NULL, BIT12_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_pwsupp_vol,
           { "SDR Power Supply Value (AIN6)" , "hpsdr-u.c.pwsupp.vol",
            FT_UINT16, BASE_HEX,
            NULL, BIT12_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_overflow_sub,
           { "ADC Overflow subtree" , "hpsdr-u.cc.overflow.sub",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_overflow_mercury1,
           { "Mercury 1 Software Version" , "hpsdr-u.cc.overflow.mercury1",
            FT_UINT8, BASE_DEC,
            NULL, SDR_MER_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_overflow_adc1,
           { "         SDR ADC1 Overflow" , "hpsdr-u.cc.overflow.adc1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_active_inactive), SDR_OVER_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_overflow_mercury2,
           { "Mercury 2 Software Version" , "hpsdr-u.cc.overflow.mercury2",
            FT_UINT8, BASE_DEC,
            NULL, SDR_MER_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_overflow_adc2,
           { "         SDR ADC2 Overflow" , "hpsdr-u.cc.overflow.adc2",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_active_inactive), SDR_OVER_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_overflow_mercury3,
           { "Mercury 3 Software Version" , "hpsdr-u.cc.overflow.mercury3",
            FT_UINT8, BASE_DEC,
            NULL, SDR_MER_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_overflow_adc3,
           { "         SDR ADC3 Overflow" , "hpsdr-u.cc.overflow.adc3",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_active_inactive), SDR_OVER_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_overflow_mercury4,
           { "Mercury 4 Software Version" , "hpsdr-u.cc.overflow.mercury4",
            FT_UINT8, BASE_DEC,
            NULL, SDR_MER_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_overflow_adc4,
           { "         SDR ADC4 Overflow" , "hpsdr-u.cc.overflow.adc4",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_active_inactive), SDR_OVER_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep6_num_of_rx_1,
           { "Number of RX" , "hpsdr-u.ep6.num-rx_1",
            FT_UINT8, BASE_DEC,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep6_num_of_rx_2,
           { "Number of RX" , "hpsdr-u.ep6.num-rx_2",
            FT_UINT8, BASE_DEC,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep6_data_1,
           { "Data", "hpsdr-u.ep6.data_1",
            FT_NONE, BASE_NONE,
            NULL, ZERO_MASK, 
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep6_data_2,
           { "Data", "hpsdr-u.ep6.data_2",
            FT_NONE, BASE_NONE,
            NULL, ZERO_MASK, 
            NULL, HFILL }
       },
       { &hf_hpsdr_u_c0_mox_1,
           { "    MOX" , "hpsdr-u.c0.mox_1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_active_inactive), HOST_C0_MOX,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_c0_mox_2,
           { "    MOX" , "hpsdr-u.c0.mox_2",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_active_inactive), HOST_C0_MOX,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep2_c0_type_1,
           { "   C0 Type" , "hpsdr-u.ep2_c0.type_1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&blank_blank), HOST_C0_TYPE,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep2_c0_type_2,
           { "   C0 Type" , "hpsdr-u.ep2_c0.type_2",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&blank_blank), HOST_C0_TYPE,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep2_data_1,
           { "Data", "hpsdr-u.ep2.data_1",
            FT_NONE, BASE_NONE,
            NULL, ZERO_MASK, 
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep2_data_2,
           { "Data", "hpsdr-u.ep2.data_2",
            FT_NONE, BASE_NONE,
            NULL, ZERO_MASK, 
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_conf_c1_1,
           { "C&C Byte 1" , "hpsdr-u.cc.cc1_1",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_conf_c2_1,
           { "C&C Byte 2" , "hpsdr-u.cc.cc2_1",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_conf_c3_1,
           { "C&C Byte 3" , "hpsdr-u.cc.cc3_1",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_conf_c4_1,
           { "C&C Byte 4" , "hpsdr-u.cc.cc4_1",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_conf_sub_1,
           { "USB EP2 C0 Config data subtree" , "hpsdr-u.cc.sub_1",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_conf_c1_2,
           { "    C&C Byte 1" , "hpsdr-u.cc.cc1_2",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_conf_c2_2,
           { "C&C Byte 2" , "hpsdr-u.cc.cc2_2",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_conf_c3_2,
           { "C&C Byte 3" , "hpsdr-u.cc.cc3_2",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_conf_c4_2,
           { "C&C Byte 4" , "hpsdr-u.cc.cc4_2",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_conf_sub_2,
           { "USB EP2 C0 Config data subtree" , "hpsdr-u.cc.sub_2",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_speed,
           { "            Speed" , "hpsdr-u.cc.speed",
            FT_UINT8, BASE_HEX,
            VALS(ep2_speed), HOST_C1_SPEED,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_10mhz,
           { "    10 MHz Source" , "hpsdr-u.cc.10mhz",
            FT_UINT8, BASE_HEX,
            VALS(ep2_10mhz), HOST_C1_10MHZ,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_122mhz,
           { "122.88 MHz Source" , "hpsdr-u.cc.122mhz",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&mercury_penelope), HOST_C1_122S,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_conf,
           { "           Config" , "hpsdr-u.cc.conf",
            FT_UINT8, BASE_HEX,
            VALS(ep2_config), HOST_C1_CONF,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_mic_s,
           { "       MIC Source" , "hpsdr-u.cc.mic-source",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&penelope_janus), HOST_C1_MICS,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_mode,
           { "Mode" , "hpsdr-u.cc.mode",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&ClassE_other), HOST_C2_MODE,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_oco_0,
           { "Open Coll Output 0" , "hpsdr-u.cc.oco-0",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_set_notset), HOST_C2_OC0,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_oco_1,
           { "Open Coll Output 1" , "hpsdr-u.cc.oco-1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_set_notset), HOST_C2_OC1,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_oco_2,
           { "Open Coll Output 2" , "hpsdr-u.cc.oco-2",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_set_notset), HOST_C2_OC2,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_oco_3,
           { "Open Coll Output 3" , "hpsdr-u.cc.oco-3",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_set_notset), HOST_C2_OC3,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_oco_4,
           { "Open Coll Output 4" , "hpsdr-u.cc.oco-4",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_set_notset), HOST_C2_OC4,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_oco_5,
           { "Open Coll Output 5" , "hpsdr-u.cc.oco-5",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_set_notset), HOST_C2_OC5,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_oco_6,
           { "Open Coll Output 6" , "hpsdr-u.cc.oco-6",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_set_notset), HOST_C2_OC6,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_ant_pre_attn,
           { "Anntena Preselector Attenuator" , "hpsdr-u.cc.ant-pre-attn",
            FT_UINT8, BASE_HEX,
            VALS(ep2_pre_attn), HOST_C3_P_ATT,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_ant_pre_pre_amp,
           { "    Anntena Preselector Preamp" , "hpsdr-u.cc.ant-pre-pre_amp",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C3_PREAM,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_adc_dither,
           { "                     IF Dither" , "hpsdr-u.cc.adc-dither",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C3_IFDIT,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_adc_random,
           { "                     IF Random" , "hpsdr-u.cc.adc-random",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C3_IFRAD,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_ant_pre_ant,
           { "Anntena Preselector RX Anntena Selection" , "hpsdr-u.cc.ant-pre-ant",
            FT_UINT8, BASE_HEX,
            VALS(ep2_pre_rx_ant), HOST_C3_P_ANT,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_ant_pre_rx_out,
           { "    Anntena Preselector RX Out" , "hpsdr-u.cc.ant-pre-rx-out",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C3_P_OUT,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_ant_pre_tx_relay,
           { "Anntena Preselector TX Relay Selection" , "hpsdr-u.cc.ant-pre-tx-relay",
            FT_UINT8, BASE_HEX,
            VALS(ep2_pre_tx_relay), HOST_C4_P_T_R,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_dup,
           { "             Duplex" , "hpsdr-u.cc.dup",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C4_DUP,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_rx_num,
           { "Number of Receivers" , "hpsdr-u.cc.rx-num",
            FT_UINT8, BASE_HEX,
            NULL, HOST_C4_RX_NU,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_mic_ts,
           { "  Mic Time Stamping" , "hpsdr-u.cc.mic-ts",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C4_T_ST,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_com_merc_freq,
           { "Common Mercury Freq" , "hpsdr-u.cc.com-merc-freq",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&same_independent), HOST_C4_C_FEQ,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep6_data_sub_1,
           { "USB EP6 Data subtree" , "hpsdr-u.ep6.data.sub_1",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep6_data_sub_2,
           { "USB EP6 Data subtree" , "hpsdr-u.ep6.data.sub_2",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep6_idx,
           { "EP2 Data Index" , "hpsdr-u.ep6.data.idx",
            FT_UINT8, BASE_DEC,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep6_rx_idx,
           { "EP2 Data RX Index" , "hpsdr-u.ep6.data.rx-idx",
            FT_UINT8, BASE_DEC,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep6_i,
           { "USB EP6 I Sample" , "hpsdr-u.ep6.data.i",
            FT_UINT24, BASE_HEX,
            NULL, BIT24_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep6_q,
           { "USB EP6 Q Sample" , "hpsdr-u.ep6.data.q",
            FT_UINT24, BASE_HEX,
            NULL, BIT24_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep6_data_string_ml,
           { "USB EP6 String for MIC/Line" , "hpsdr-u.ep6.data.string-ml",
            FT_STRING, STR_ASCII,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep6_ml,
           { "USB  EP6  MIC/Line  Sample" , "hpsdr-u.ep6.data.ml",
            FT_UINT16, BASE_HEX,
            NULL, BIT16_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep6_data_string_end,
           { "USB EP6 String for end" , "hpsdr-u.ep6.data.string-end",
            FT_STRING, STR_ASCII,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep6_data_pad,
           { "EP6 Data Pad" , "hpsdr-u.ep6.data.pad",
            FT_NONE, BASE_NONE,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_nco_tx,
           { "TX NCO Frequency" , "hpsdr-u.cc.nco-tx",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_nco_rx_1,
           { "RX 1 NCO Frequency" , "hpsdr-u.cc.nco-rx-1",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_nco_rx_2,
           { "RX 2 NCO Frequency" , "hpsdr-u.cc.nco-rx-2",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_nco_rx_3,
           { "RX 3 NCO Frequency" , "hpsdr-u.cc.nco-rx-3",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_nco_rx_4,
           { "RX 4 NCO Frequency" , "hpsdr-u.cc.nco-rx-4",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_nco_rx_5,
           { "RX 5 NCO Frequency" , "hpsdr-u.cc.nco-rx-5",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_nco_rx_6,
           { "RX 6 NCO Frequency" , "hpsdr-u.cc.nco-rx-6",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_nco_rx_7,
           { "RX 7 NCO Frequency" , "hpsdr-u.cc.nco-x-7",
            FT_UINT32, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_tx_drive,
           { "TX Drive Level" , "hpsdr-u.cc.tx-drive",
            FT_UINT8, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_filter_sub,
           { "USB EP2 C0 Config filter subtree" , "hpsdr-u.cc.filter.sub",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_mic_boost,
           { "                Mic Boost" , "hpsdr-u.cc.mic-boost",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&zero_20), HOST_C2_MIC_B,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_mic_l,
           { "           Mic or Line In" , "hpsdr-u.cc.mic-l",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&line_mic), HOST_C2_MIC_L,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_apollo_filter,
           { "   Hermes - Apollo Filter" , "hpsdr-u.cc.apollo-filter",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C2_E_T_F ,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_apollo_tunner,
           { "    Hermes - Apollo Tuner" , "hpsdr-u.cc.apollo-tunner",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C2_EN_TU,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_apollo_auto,
           { "Hermes - Apollo Auto Tune" , "hpsdr-u.cc.apollo.auto",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&start_end), HOST_C2_AU_TU,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_herm_fil_s,
           { "    Hermes - Filter Board" , "hpsdr-u.cc.herm-filter-sel",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&apollo_alex), HOST_C2_AL_AP,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_filter_man,
           { "Alex Manual Filter Select" , "hpsdr-u.cc.ant-pre-man",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C2_AP_MA,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_vna,
           { "                 VNA Mode" , "hpsdr-u.cc.vna",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C2_VNA,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_hpf_13,
           { "Alex  13MHZ HPF" , "hpsdr-u.cc.hpf_13",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C3_F_13,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_hpf_20,
           { "Alex  20MHZ HPF" , "hpsdr-u.cc.hpf_20",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C3_F_20,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_hpf_9_5,
           { "Alex 9.5MHZ HPF" , "hpsdr-u.cc.hpf_9-5",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C3_F_9_5,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_hpf_6_5,
           { "Alex 6.5MHZ HPF" , "hpsdr-u.cc.hpf_6-5",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C3_F_6_5,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_hpf_1_5,
           { "Alex 1.5MHZ HPF" , "hpsdr-u.cc.hpf_1-5",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C3_F_1_5,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_bypass_hpf,
           { "Alex Bypass HPF" , "hpsdr-u.cc.bypass-hpf",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C3_HPF_B,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_6m_amp,
           { "Alex     6M Amp" , "hpsdr-u.cc.6m-amp",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C3_6M_B,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_dis_ant_pre_tr,
           { "Alex Disable T/R Relay" , "hpsdr-u.cc.dis-ant-pre",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C3_D_P_R,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_ep2_c4_12,
           { "C&C Byte 4" , "hpsdr-u.cc.ep2.cc4.12",
            FT_UINT8, BASE_HEX,
            NULL, HOST_C4_T_12,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_lpf_30_20,
           { "Alex 30/20m LPF" , "hpsdr-u.cc.lpf_30-20",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C4_20_30,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_lpf_60_40,
           { "Alex 60/40m LPF" , "hpsdr-u.cc.lpf_60-40",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C4_60_40,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_lpf_80,
           { "Alex    80m LPF" , "hpsdr-u.cc.lpf_80",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C4_F_80,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_lpf_160,
           { "Alex   160m LPF" , "hpsdr-u.cc.lpf_160",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C4_F_160,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_lpf_6,
           { "Alex     6m LPF" , "hpsdr-u.cc.lpf_6",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C4_F_6,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_lpf_12_10,
           { "Alex 12-10m LPF" , "hpsdr-u.cc.lpf_12-10",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C4_12_10,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_lpf_17_15,
           { "Alex 17-15m LPF" , "hpsdr-u.cc.lpf_17-15",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C4_17_15,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_ep2_c1_14,
           { "C&C Byte 1" , "hpsdr-u.cc.ep2.c1.14",
            FT_UINT8, BASE_HEX,
            NULL, HOST_C1_2_14,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_rx1_preamp,
           { "              RX1 Pre-Amp" , "hpsdr-u.cc.rx1-preamp",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C1_RX1P,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_rx2_preamp,
           { "              RX2 Pre-Amp" , "hpsdr-u.cc.rx2-preamp",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C1_RX2P,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_rx3_preamp,
           { "              RX3 Pre-Amp" , "hpsdr-u.cc.rx3-preamp",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C1_RX3P,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_rx4_preamp,
           { "              RX4 Pre-Amp" , "hpsdr-u.cc.rx4-preamp",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C1_RX4P,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_orion_mic_tr,
           { "Orion Mic Tip/Ring Select" , "hpsdr-u.cc.orion-mic_tip-ring",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&tip_ring), HOST_C1_O_TR,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_orion_mic_bias,
           { "           Orion Mic Bias" , "hpsdr-u.cc.orion-mic-bias",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C1_O_B,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_orion_mic_ptt,
           { "            Orion Mic PTT" , "hpsdr-u.cc.orion-mic-ptt",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_disabled_enabled), HOST_C1_O_PT,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_codec_line_gain,
           { "  Codec (TLV320) Line Gain" , "hpsdr-u.cc.codec-line-gain",
            FT_UINT8, BASE_DEC,
            NULL, HOST_C2_TLV,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_merc_tx_atten_c2,
           { "If Set, Mercury 20dB on TX" , "hpsdr-u.cc.merc-tx-atten-c2",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_set_notset), HOST_C2_A_TX,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_pure_signal,
           { "                PureSignal" , "hpsdr-u.cc.pure-signal",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C2_PURE,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_penelope_cw,
           { "	     Penelope Selected" , "hpsdr-u.cc.penelope-cw",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C2_P_CW,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_ep2_c3_14,
           { "C&C Byte 3" , "hpsdr-u.cc.ep2.c3.14",
            FT_UINT8, BASE_HEX,
            NULL, HOST_C3_2_14,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_metis_p1,
           { "Metis DB9 Pin 1 Open Drain Output" , "hpsdr-u.cc.metis-p1",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C3_M_P1,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_metis_p2,
           { "Metis DB9 Pin 2 Open Drain Output" , "hpsdr-u.cc.metis-p2",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C3_M_P2,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_metis_p3,
           { "Metis DB9 Pin 3  3.3v TTL  Output" , "hpsdr-u.cc.metis-p3",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C3_M_P3,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_metis_p4,
           { "Metis DB9 Pin 4  3.3v TTL  Output" , "hpsdr-u.cc.metis-p4",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C3_M_P4,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_merc_tx_atten_c3,
           { "              Mercury 20 dB on TX" , "hpsdr-u.cc.merc-tx-atten-c3",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C3_A_TX,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_ep2_c4_14,
           { "C&C Byte 4" , "hpsdr-u.cc.ep2.c4.14",
            FT_UINT8, BASE_HEX,
            NULL, HOST_C4_2_14,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_adc1_rx_atten,
           { "   ADC1 RX Input Attenuator" , "hpsdr-u.cc.adc1-rx-atten",
            FT_UINT8, BASE_DEC,
            NULL, HOST_C4_A1_A,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_herm_angelia_atten,
           { "Hermes / Angelia Attenuator" , "hpsdr-u.cc.herm_angelia-atten",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&ha_a_enabled_disabled), HOST_C4_HA_A,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_ep2_c1_16,
           { "C&C Byte 1" , "hpsdr-u.cc.ep2.c1.16",
            FT_UINT8, BASE_HEX,
            NULL, HOST_C1_2_16,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_adc2_rx_atten,
           { " ADC2 RX Input Attenuator" , "hpsdr-u.cc.adc2-rx-atten",
            FT_UINT8, BASE_DEC,
            NULL, HOST_2_16_ADC,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_adc2_en,
           { "ADC2 RX Input Attn Enable" , "hpsdr-u.cc.adc2.en",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&adc_enabled_disabled), HOST_2_16_AS,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_ep2_c2_16,
           { "C&C Byte 2" , "hpsdr-u.cc.ep2.c2.16",
            FT_UINT8, BASE_HEX,
            NULL, HOST_C2_2_16,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_adc3_rx_atten,
           { " ADC3 RX Input Attenuator" , "hpsdr-u.cc.adc3-rx-atten",
            FT_UINT8, BASE_DEC,
            NULL, HOST_2_16_ADC,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_adc3_en,
           { "ADC3 RX Input Attn Enable" , "hpsdr-u.cc.adc3.en",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&adc_enabled_disabled), HOST_2_16_AS,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_cw_rev,
           { "          CW Key Reversed" , "hpsdr-u.cc.cw-rev",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_enabled_disabled), HOST_C2_CW_R,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_cw_keyer_speed,
           { "CW Keyer Speed" , "hpsdr-u.cc.cw-keyer-speed",
            FT_UINT8, BASE_DEC,
            NULL, HOST_C3_CW_S,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_cw_keyer_mode,
           { " CW Keyer Mode" , "hpsdr-u.cc.cw-keyer-mode",
            FT_UINT8, BASE_DEC,
            VALS(ep2_cw_mode), HOST_C3_CW_KM,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_cw_keyer_weight,
           { "  CW Keyer Weight" , "hpsdr-u.cc.cw-keyer-weight",
            FT_UINT8, BASE_DEC,
            NULL, HOST_C4_CW_KW,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_cw_keyer_spacing,
           { "CW Keyer Spaceing" , "hpsdr-u.cc.cw-keyer-spaceing",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&local_on_off), HOST_C4_CW_KS,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_rx1_adc_assign,
           { "RX1 ADC Assignment" , "hpsdr-u.cc.rx1-adc-assign",
            FT_UINT8, BASE_DEC,
            VALS(ep2_adc_asign), HOST_C1_R1_AD,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_rx2_adc_assign,
           { "RX2 ADC Assignment" , "hpsdr-u.cc.rx2-adc-assign",
            FT_UINT8, BASE_DEC,
            VALS(ep2_adc_asign), HOST_C1_R2_AD,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_rx3_adc_assign,
           { "RX3 ADC Assignment" , "hpsdr-u.cc.rx3-adc-assign",
            FT_UINT8, BASE_DEC,
            VALS(ep2_adc_asign), HOST_C1_R3_AD,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_rx4_adc_assign,
           { "RX4 ADC Assignment" , "hpsdr-u.cc_rx4-adc-assign",
            FT_UINT8, BASE_DEC,
            VALS(ep2_adc_asign), HOST_C1_R4_AD,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_ep2_c2_1c,
           { "C&C Byte 2" , "hpsdr-u.cc.ep2.c2.1c",
            FT_UINT8, BASE_HEX,
            NULL, HOST_C2_2_1E,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_rx5_adc_assign,
           { "RX5 ADC Assignment" , "hpsdr-u.cc.rx5-adc-assign",
            FT_UINT8, BASE_DEC,
            VALS(ep2_adc_asign), HOST_C2_R5_AD,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_rx6_adc_assign,
           { "RX6 ADC Assignment" , "hpsdr-u.cc.rx6-adc-assign",
            FT_UINT8, BASE_DEC,
            VALS(ep2_adc_asign), HOST_C2_R6_AD,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_rx7_adc_assign,
           { "RX7 ADC Assignment" , "hpsdr-u.cc.rx7-adc-assign",
            FT_UINT8, BASE_DEC,
            VALS(ep2_adc_asign), HOST_C2_R7_AD,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_adc_input_atten_tx,
           { "C&C Byte 3- ADC Input TX Atten" , "hpsdr-u.cc.adc-input-atten-tx",
            FT_UINT8, BASE_DEC,
            NULL, HOST_C3_A_I_A,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_cw_source,
           { "CW Source         " , "hpsdr-u.cc.cw-source",
            FT_BOOLEAN, BOOLEAN_MASK,
            TFS(&internal_external), HOST_C1_CW_SO,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_cw_sidetone_vol,
           { "CW Sidetone Volume" , "hpsdr-u.cc.cw-sidetone-vol",
            FT_UINT8, BASE_DEC,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_cw_ptt_delay,
           { "CW PTT Delay      " , "hpsdr-u.cc.cw-ptt-delay",
            FT_UINT8, BASE_DEC,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_cw_hang_time,
           { "CW Hang Time    " , "hpsdr-u.cc.cw-hang-time",
            FT_UINT16, BASE_DEC,
            NULL, HOST_2_20_CW_H,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_cw_sidetone_freq,
           { "CW Sidetone Freq" , "hpsdr-u.cc.cw-sidetone-freq",
            FT_UINT16, BASE_DEC,
            NULL, HOST_2_20_CW_F,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_pwm_min,
           { "PWM Min Pulse Width" , "hpsdr-u.cc.pwm-min",
            FT_UINT16, BASE_DEC,
            NULL, HOST_2_22,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_cc_pwm_max,
           { "PWM Max Pulse Width" , "hpsdr-u.cc.pwm-max",
            FT_UINT16, BASE_DEC,
            NULL, HOST_2_22,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep2_data_sub_1,
           { "USB EP2 Data subtree" , "hpsdr-u.ep2.data.sub_1",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep2_data_sub_2,
           { "USB EP2 Data subtree" , "hpsdr-u.ep2.data.sub_2",
            FT_UINT8, BASE_HEX,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep2_l,
           { "USB EP2 Left  Audio Sample" , "hpsdr-u.ep2.data.l",
            FT_UINT16, BASE_HEX,
            NULL, BIT16_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep2_r,
           { "USB EP2 Right Audio Sample" , "hpsdr-u.ep2.data.r",
            FT_UINT16, BASE_HEX,
            NULL, BIT16_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep2_i,
           { "USB EP2 I Sample          " , "hpsdr-u.ep2.data.i",
            FT_UINT16, BASE_HEX,
            NULL, BIT16_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep2_q,
           { "USB EP2 Q Sample          " , "hpsdr-u.ep2.data.q",
            FT_UINT16, BASE_HEX,
            NULL, BIT16_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep2_idx,
           { "EP2 Data Index" , "hpsdr-u.ep2.data.idx",
            FT_UINT8, BASE_DEC,
            NULL, ALL_BITS_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep4_separator,
           { "Wide Band Data Sample Separator" , "hpsdr-u.ep4.separator",
            FT_STRING, STR_ASCII,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
       { &hf_hpsdr_u_ep4_sample_idx ,
           { "EP 4 Sample Index", "hpsdr-u.ep4.sample-idx",
            FT_UINT16, BASE_DEC,
            NULL, ZERO_MASK,
            NULL, HFILL }
       }, 
       { &hf_hpsdr_u_ep4_sample,
           { "Wide Band Sample", "hpsdr-u.ep4.sample",
            FT_UINT16, BASE_HEX,
            NULL, ZERO_MASK,
            NULL, HFILL }
       },
   };

   /* protocol subtree array */
   static gint *ett[] = {
        &ett_hpsdr_u,
        &ett_hpsdr_u_f1,
        &ett_hpsdr_u_f2,
        &ett_hpsdr_u_c0,
        &ett_hpsdr_u_cc_conf,
        &ett_hpsdr_u_cc_filter,
        &ett_hpsdr_u_cc_misc,
        &ett_hpsdr_u_cc_adc_cw,
        &ett_hpsdr_u_cc_rx_adc,
        &ett_hpsdr_u_cc_cw1,
        &ett_hpsdr_u_cc_cw2,
        &ett_hpsdr_u_cc_pwm,
        &ett_hpsdr_u_ep2_data_1,
        &ett_hpsdr_u_ep2_data_2,
        &ett_hpsdr_u_cc_info,
        &ett_hpsdr_u_cc_fp,
        &ett_hpsdr_u_cc_rp,
        &ett_hpsdr_u_cc_ps,
        &ett_hpsdr_u_cc_ov,
        &ett_hpsdr_u_ep6_data_1,
        &ett_hpsdr_u_ep6_data_2,
   };
   
   /* Setup protocol expert items */
   static ei_register_info ei[] = {
       { &ei_ep2_sync,
           { "ep2.sync.error", PI_MALFORMED, PI_WARN,
             "Late EP2 Sync", EXPFILL }
       },
       { &ei_extra_length,
           { "extra-length", PI_MALFORMED, PI_WARN,
             "Extra Bytes", EXPFILL }
       },
   };

   proto_hpsdr_u = proto_register_protocol (
        "HPSDR USB Over IP", /* name       */
        "HPSDR-USB",        /* short name */
        "hpsdr-u"          /* abbrev     */
   );

   proto_register_field_array(proto_hpsdr_u, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));

   /* Required function calls to register expert items */
   expert_hpsdr_u = expert_register_protocol(proto_hpsdr_u);
   expert_register_field_array(expert_hpsdr_u, ei, array_length(ei));

    //Register configuration preferences
   hpsdr_u_prefs = prefs_register_protocol(proto_hpsdr_u,NULL);

   prefs_register_bool_preference(hpsdr_u_prefs,"strict_size",
       "Strict Checking of Datagram Size",
       "Disable checking for added bytes at the end of the datagrams."
       " Disables the warning message.",
       &hpsdr_u_strict_size);
 
   prefs_register_bool_preference(hpsdr_u_prefs,"strict_pad",
       "Strict Pad Checking",  
       "Strict checking of the amount of pad bytes at the end of the datagrams."
       " When enabled, Wireshark (not the openHPSDR dissector) will display"
       " a \"Malformed Packet\" error for a datagram without the correct"
       " number of pad bytes." 
       " When disabled, checking is only for one pad byte instead of checking"
       " for the correct number of pad bytes.", 
       &hpsdr_u_strict_pad);

   prefs_register_bool_preference(hpsdr_u_prefs,"ep2_sync",
       "End Point 2 Sync Checking",  
       "Some Host applications add extra bytes in front of the USB end point 2"
       " data. When disabled, there will be no checking for the insertion of"
       " extra bytes.",       
       &hpsdr_u_ep2_sync);
}

gint packet_end_pad(tvbuff_t *tvb, proto_tree *tree, gint offset, gint size)
{ 
   gint length = -1;

   proto_item *local_append_text_item = NULL;

   if (hpsdr_u_strict_pad) { length = size; }
   else { length = 1; }

   local_append_text_item = proto_tree_add_item(tree,hf_hpsdr_u_pad,tvb,offset,
                         length,ENC_BIG_ENDIAN);
               
   if (hpsdr_u_strict_pad) { proto_item_append_text(local_append_text_item," (%d Bytes)",size); }
   else { proto_item_append_text(local_append_text_item," (%d Bytes) -Disabled",size); }
   offset += size; 

   return offset;
}

void check_length(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
 
   guint length_remaining = -1;
   const char *placehold = NULL ;

   proto_item *ei_item = NULL;

   if ( !(hpsdr_u_strict_size) ) { return; }

   if ( tvb_captured_length(tvb) > (guint)offset) {
       length_remaining = tvb_ensure_captured_length_remaining(tvb, offset); 
       ei_item = proto_tree_add_string_format(tree, hf_hpsdr_u_ei, tvb, 
                     offset, length_remaining, placehold,"Extra Length");
       expert_add_info_format(pinfo,ei_item,&ei_extra_length,
           "Extra Bytes in packet, %d extra bytes.",length_remaining);
   }
                 
}



static int hpsdr_usb_ep2_frame(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int frame_num) {

   //Submenu items
   proto_item *c0_item = NULL;
   proto_item *cc_conf_item = NULL;
   proto_item *c0_type_item = NULL;
   proto_item *cc_filter_item = NULL;
   proto_item *cc_misc_item = NULL;
   proto_item *cc_adc_cw_item = NULL;
   proto_item *cc_rx_adc_item = NULL;
   proto_item *cc_cw1_item = NULL;
   proto_item *cc_cw2_item = NULL;
   proto_item *cc_pwm_item = NULL;
   proto_item *ep2_data_item = NULL;

   proto_item *ei_sync_item = NULL;
   proto_item *append_text_item = NULL;

   proto_tree *hpsdr_u_tree_c0 = NULL;
   proto_tree *hpsdr_u_tree_cc_conf = NULL;
   proto_tree *hpsdr_u_tree_cc_filter = NULL;
   proto_tree *hpsdr_u_tree_cc_misc = NULL;
   proto_tree *hpsdr_u_tree_cc_adc_cw = NULL;
   proto_tree *hpsdr_u_tree_cc_rx_adc = NULL;
   proto_tree *hpsdr_u_tree_cc_cw1 = NULL;
   proto_tree *hpsdr_u_tree_cc_cw2 = NULL;
   proto_tree *hpsdr_u_tree_cc_pwm = NULL;
   proto_tree *hpsdr_u_tree_ep2_data = NULL;

   guint8 C0 = -1;
   guint8 C0_masked =-1;
   guint8 C1 =-1;
   guint8 C2 = -1;
   guint8 C3 = -1;
   guint8 C4 = -1;

   guint16 high_byte = -1;
   guint16 final_byte = -1;
   guint16 L = -1;
   guint16 R = -1;
   guint16 I = -1;
   guint16 Q = -1;

   int *sync = NULL;
   int *c0_sub = NULL;
   int *u_c0 = NULL;
   int *c0_mox = NULL; 
   int *c0_type = NULL;
   int *cc_conf_c1 = NULL;
   int *cc_conf_c2 = NULL;
   int *cc_conf_c3 = NULL;
   int *cc_conf_c4 = NULL;
   int *cc_conf_sub = NULL;
   int *ett_ep2_data = NULL;
   int *ep2_data_sub = NULL; 

   int sync_error = 0;
   int ep2_0_rx_num = -1;
   int  x = -1;

   switch ( frame_num ) {
 
       case 1:  
              sync = &hf_hpsdr_u_sync_1;
              c0_sub = &hf_hpsdr_u_c0_sub_1;
              u_c0 = &hf_hpsdr_u_c0_1;
              c0_mox = &hf_hpsdr_u_c0_mox_1;
              c0_type = &hf_hpsdr_u_c0_type_1;
              ett_ep2_data = &ett_hpsdr_u_ep2_data_1;
              ep2_data_sub = &hf_hpsdr_u_ep2_data_sub_1;
              cc_conf_c1 = &hf_hpsdr_u_cc_conf_c1_1;
              cc_conf_c2 = &hf_hpsdr_u_cc_conf_c2_1;
              cc_conf_c3 = &hf_hpsdr_u_cc_conf_c3_1;         
              cc_conf_c4 = &hf_hpsdr_u_cc_conf_c4_1;
              cc_conf_sub = &hf_hpsdr_u_cc_conf_sub_1;

              break;

       case 2:  
              sync = &hf_hpsdr_u_sync_2;
              c0_sub = &hf_hpsdr_u_c0_sub_2;
              u_c0 = &hf_hpsdr_u_c0_2;
              c0_mox = &hf_hpsdr_u_c0_mox_2;
              c0_type = &hf_hpsdr_u_c0_type_2;
              ett_ep2_data = &ett_hpsdr_u_ep2_data_2;
              ep2_data_sub = &hf_hpsdr_u_ep2_data_sub_2;
              cc_conf_c1 = &hf_hpsdr_u_cc_conf_c1_2;
              cc_conf_c2 = &hf_hpsdr_u_cc_conf_c2_2;
              cc_conf_c3 = &hf_hpsdr_u_cc_conf_c3_2;         
              cc_conf_c4 = &hf_hpsdr_u_cc_conf_c4_2;
              cc_conf_sub = &hf_hpsdr_u_cc_conf_sub_2;           
              break;
   }
  
   // Find Sync
   // Needed because host appilcations do behave VERY BADLY !!!!!!!
   while ( hpsdr_u_ep2_sync && (tvb_get_guint24(tvb, offset,3) != 0x7F7F7F) ) {  
       offset +=1;
       sync_error +=1; 
   }

   ei_sync_item = proto_tree_add_item(tree, *sync, tvb,offset, 3, ENC_BIG_ENDIAN);
   
   if ( hpsdr_u_ep2_sync && sync_error > 0 ) { 
           expert_add_info_format(pinfo,ei_sync_item,&ei_ep2_sync,
               "EP2 Sync at wrong location, %d extra bytes.",sync_error); 
   }

   offset += 3;
 
   C0 = tvb_get_guint8(tvb, offset);
   c0_item = proto_tree_add_uint_format(tree, *c0_sub, tvb, offset, 1,
                C0, "C&C Byte 0  : 0x%02X",C0 );

   hpsdr_u_tree_c0 = proto_item_add_subtree(c0_item, ett_hpsdr_u_c0);

   proto_tree_add_item(hpsdr_u_tree_c0, *u_c0, tvb,offset, 1, ENC_BIG_ENDIAN);
   //C0_masked = ( C0 & 0b11111110 ) ; // bitwise and
   C0_masked = ( C0 & 0xFE ) ;

   proto_tree_add_boolean(hpsdr_u_tree_c0, *c0_mox, tvb,offset, 1, C0);             
   c0_type_item = proto_tree_add_boolean(hpsdr_u_tree_c0, *c0_type, tvb,offset, 1, C0_masked );
   proto_item_append_text(c0_type_item," 0x%02X", C0_masked);
   offset += 1;

                    //00 Configuration
                   //02 TX NCO Frequency
                  //04 RX 1 NCO Frequency
                 //06 RX 2 NCO Frequency
                //08 RX 3 NCO Frequency
               //0A RX 4 NCO Frequency
              //0C RX 5 NCO Frequency
             //0E RX 6 NCO Frequency
            //10 RX 7 NCO Frequency
           //12 TX Drive, Anntena Presect, VNA
          //14 RX Pre-amp, IF Gain, PureSignal, Open Drain, TTL, 20db/ADC1 Attn
         //16 ADC[123] Attn, CW Config
        //18 Additional Mercury 1
       //1A Additional Mercury 2
      //1C ADC RX Assignment 
     //1E CW Configuration 2
    //20 CW Configuration 3
   //22 PWM Configuration
   
   if ( C0_masked == 0x0 )  { // Configuration

       cc_conf_item = proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
                          C0_masked, "C0 Type 0x%02X: SDR Configuration",C0_masked);
       hpsdr_u_tree_cc_conf = proto_item_add_subtree(cc_conf_item, ett_hpsdr_u_cc_conf);

       C1 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_conf, *cc_conf_c1, tvb,offset, 1, ENC_BIG_ENDIAN);

       proto_tree_add_item(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_speed, tvb,offset, 1, C1);   
       proto_tree_add_item(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_10mhz, tvb,offset, 1, C1);
       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_122mhz, tvb,offset, 1, C1);
       proto_tree_add_item(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_conf, tvb,offset, 1, C1);
       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_mic_s,tvb,offset, 1, C1); 
       offset += 1;

       C2 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_conf, *cc_conf_c2, tvb,offset, 1, ENC_BIG_ENDIAN);

       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_mode,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_oco_0,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_oco_1,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_oco_2,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_oco_3,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_oco_4,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_oco_5,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_oco_6,tvb,offset, 1, C2);
       offset += 1;

       C3 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_conf, *cc_conf_c3, tvb,offset, 1, ENC_BIG_ENDIAN);

       proto_tree_add_item(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_ant_pre_attn,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_ant_pre_pre_amp,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_adc_dither,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_adc_random,tvb,offset, 1, C3);
       proto_tree_add_item(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_ant_pre_ant,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_ant_pre_rx_out,tvb,offset, 1, C3);
       offset += 1;

       C4 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_conf, *cc_conf_c4, tvb,offset, 1, ENC_BIG_ENDIAN);

       //ep2_0_rx_num = ( ( (C4 & 0b00111000) >> 3 ) + 1) ; // bitwise and shift right 3 bits 
       ep2_0_rx_num = ( ( (C4 & 0x38) >> 3 ) + 1) ;
 
       // Get and save num of RX - When the IQ state is STOP.
       if ( ((global_flags & GF_BW_IQ_ST_ST) == 0) | ((global_flags & GF_BW_IQ_ST_ST) == 5) ) {
           rx_num = ep2_0_rx_num;  
       }

       proto_tree_add_item(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_ant_pre_tx_relay,tvb,offset, 1, C4);
       proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_dup,tvb,offset, 1, C4);

       append_text_item = proto_tree_add_item(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_rx_num,tvb,offset, 1, C4);
       proto_item_append_text(append_text_item," : %d RX", rx_num );

       append_text_item = proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_mic_ts,tvb,offset, 1, C4);
       proto_item_append_text(append_text_item," : 1PPS on LBS of MIC Data");

       append_text_item = proto_tree_add_boolean(hpsdr_u_tree_cc_conf, hf_hpsdr_u_cc_com_merc_freq,tvb,offset, 1, C4);
       proto_item_append_text(append_text_item," : Used with Multi Mercury"); 

       offset += 1;

   } else if ( C0_masked == 0x02 ) { // TX NCO Frequency

       proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
           C0_masked, "C0 Type 0x%02X: TX NCO Frequency",C0_masked);
       append_text_item =  proto_tree_add_item(tree, hf_hpsdr_u_cc_nco_tx,tvb,offset, 4, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Hz");
       offset += 4;

   } else if ( C0_masked == 0x04 ) { // RX 1 NCO Frequency

       proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
           C0_masked, "C0 Type 0x%02X: RX 1 NCO Frequency",C0_masked);
       append_text_item =  proto_tree_add_item(tree, hf_hpsdr_u_cc_nco_rx_1,tvb,offset, 4, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Hz");
       offset += 4;

   } else if ( C0_masked == 0x06 ) { // RX 2 NCO Frequency

       proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
           C0_masked, "C0 Type 0x%02X: RX 2 NCO Frequency",C0_masked);
       append_text_item =  proto_tree_add_item(tree, hf_hpsdr_u_cc_nco_rx_2,tvb,offset, 4, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Hz");
       offset += 4;

   } else if ( C0_masked == 0x08 ) { // RX 3 NCO Frequency

       proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
           C0_masked, "C0 Type 0x%02X: RX 3 NCO Frequency",C0_masked);
       append_text_item =  proto_tree_add_item(tree, hf_hpsdr_u_cc_nco_rx_3,tvb,offset, 4, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Hz");
       offset += 4;

   } else if ( C0_masked == 0x0A ) { // RX 4 NCO Frequency

       proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
           C0_masked, "C0 Type 0x%02X: RX 4 NCO Frequency",C0_masked);
       append_text_item =  proto_tree_add_item(tree, hf_hpsdr_u_cc_nco_rx_4,tvb,offset, 4, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Hz");
       offset += 4;

   } else if ( C0_masked == 0x0C ) { // RX 5 NCO Frequency

       proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
           C0_masked, "C0 Type 0x%02X: RX 5 NCO Frequency",C0_masked);
       append_text_item =  proto_tree_add_item(tree, hf_hpsdr_u_cc_nco_rx_5,tvb,offset, 4, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Hz");
       offset += 4;

   } else if ( C0_masked == 0x0E ) { // RX 6 NCO Frequency

       proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
           C0_masked, "C0 Type 0x%02X: RX 6 NCO Frequency",C0_masked);
       append_text_item =  proto_tree_add_item(tree, hf_hpsdr_u_cc_nco_rx_6,tvb,offset, 4, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Hz");
       offset += 4;

   } else if ( C0_masked == 0x10 ) { // RX 7 NCO Frequency

       proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
           C0_masked, "C0 Type 0x%02X: RX 7 NCO Frequency",C0_masked);
       append_text_item =  proto_tree_add_item(tree, hf_hpsdr_u_cc_nco_rx_7,tvb,offset, 4, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," Hz");
       offset += 4;

   } else if ( C0_masked == 0x12 ) { // TX Drive, Anntena Presect, VNA 

       proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
           C0_masked, "C0 Type 0x%02X: TX Drive, HPF and LPF, VNA",C0_masked);
     
       proto_tree_add_item(tree,hf_hpsdr_u_cc_tx_drive,tvb,offset, 1, ENC_BIG_ENDIAN);
       offset += 1;

       cc_filter_item = proto_tree_add_uint_format(tree, hf_hpsdr_u_cc_filter_sub, tvb, offset, 3,
                            C0_masked, "C&C C2,C3,C4 - HPF and LPF, VNA");
       hpsdr_u_tree_cc_filter = proto_item_add_subtree(cc_filter_item, ett_hpsdr_u_cc_filter);

       C2 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_filter, *cc_conf_c2, tvb,offset, 1, ENC_BIG_ENDIAN);

       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_mic_boost,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_mic_l,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_apollo_filter,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_apollo_tunner,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_apollo_auto,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_herm_fil_s,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_filter_man,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_vna,tvb,offset, 1, C2);
       offset += 1;

       C3 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_filter, *cc_conf_c3, tvb,offset, 1, ENC_BIG_ENDIAN);

       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_hpf_13,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_hpf_20,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_hpf_9_5,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_hpf_6_5,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_hpf_1_5,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_bypass_hpf,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_6m_amp,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_dis_ant_pre_tr,tvb,offset, 1, C3);
       offset += 1;

       C4 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_ep2_c4_12, tvb,offset, 1, ENC_BIG_ENDIAN);

       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_lpf_30_20,tvb,offset, 1, C4);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_lpf_60_40,tvb,offset, 1, C4);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_lpf_80,tvb,offset, 1, C4);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_lpf_160,tvb,offset, 1, C4);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_lpf_6,tvb,offset, 1, C4);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_lpf_12_10,tvb,offset, 1, C4);
       proto_tree_add_boolean(hpsdr_u_tree_cc_filter, hf_hpsdr_u_cc_lpf_17_15,tvb,offset, 1, C4);
       offset += 1;

   } else if ( C0_masked == 0x14 ) { // RX Pre-amp, IF Gain, PureSignal, Open Drain, TTL, 20db/ADC1 Attn

       cc_misc_item = proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4, C0_masked, 
                          "C0 Type 0x%02X: RX Pre-amp, IF Gain, PureSignal, Open Drain, TTL, 20db/ADC1 Attn",C0_masked);
       hpsdr_u_tree_cc_misc = proto_item_add_subtree(cc_misc_item, ett_hpsdr_u_cc_misc);

       C1 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_ep2_c1_14 , tvb,offset, 1, ENC_BIG_ENDIAN);

       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_rx1_preamp,tvb,offset, 1, C1);
       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_rx2_preamp,tvb,offset, 1, C1);
       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_rx3_preamp,tvb,offset, 1, C1);
       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_rx4_preamp,tvb,offset, 1, C1);
       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_orion_mic_tr,tvb,offset, 1, C1);
       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_orion_mic_bias,tvb,offset, 1, C1);
       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_orion_mic_ptt,tvb,offset, 1, C1);
       offset += 1;

       C2 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_misc, *cc_conf_c2 , tvb,offset, 1, ENC_BIG_ENDIAN);

       append_text_item = proto_tree_add_item(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_codec_line_gain , tvb,offset, 1, C2);
       proto_item_append_text(append_text_item," :Line Boost Value for Ethernet Boards");

       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_merc_tx_atten_c2,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_pure_signal,tvb,offset, 1, C2);
       append_text_item = proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_penelope_cw,tvb,offset, 1, C2);
       proto_item_append_text(append_text_item," :Used for CW");

       offset += 1;

       C3 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_ep2_c3_14 , tvb,offset, 1, ENC_BIG_ENDIAN);

       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_metis_p1,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_metis_p2,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_metis_p3,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_metis_p4,tvb,offset, 1, C3);
       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_merc_tx_atten_c3,tvb,offset, 1, C3);
       offset += 1;

       C4 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_ep2_c4_14 , tvb,offset, 1, ENC_BIG_ENDIAN);

       append_text_item = proto_tree_add_item(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_adc1_rx_atten, tvb,offset, 1, C4);
       proto_item_append_text(append_text_item," dB");

       proto_tree_add_boolean(hpsdr_u_tree_cc_misc, hf_hpsdr_u_cc_herm_angelia_atten,tvb,offset, 1, C4);
       offset += 1;

   } else if ( C0_masked == 0x16 ) { // ADC[123] Attn, CW Config

       cc_adc_cw_item = proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
                            C0_masked, "C0 Type 0x%02X: ADC[123] Attn, CW Config",C0_masked);
       hpsdr_u_tree_cc_adc_cw = proto_item_add_subtree(cc_adc_cw_item, ett_hpsdr_u_cc_adc_cw);

       C1 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_adc_cw, hf_hpsdr_u_cc_ep2_c1_16 , tvb,offset, 1, ENC_BIG_ENDIAN);
  
       append_text_item = proto_tree_add_item(hpsdr_u_tree_cc_adc_cw, hf_hpsdr_u_cc_adc2_rx_atten, tvb,offset, 1, C1);
       proto_item_append_text(append_text_item," dB");    
  
       proto_tree_add_boolean(hpsdr_u_tree_cc_adc_cw, hf_hpsdr_u_cc_adc2_en,tvb,offset, 1, C1);     
       offset += 1;

       C2 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_adc_cw, hf_hpsdr_u_cc_ep2_c2_16 , tvb,offset, 1, ENC_BIG_ENDIAN);
  
       append_text_item = proto_tree_add_item(hpsdr_u_tree_cc_adc_cw, hf_hpsdr_u_cc_adc3_rx_atten, tvb,offset, 1, C2);
       proto_item_append_text(append_text_item," dB");    
  
       proto_tree_add_boolean(hpsdr_u_tree_cc_adc_cw, hf_hpsdr_u_cc_adc3_en,tvb,offset, 1, C2);
       proto_tree_add_boolean(hpsdr_u_tree_cc_adc_cw, hf_hpsdr_u_cc_cw_rev,tvb,offset, 1, C2);     
       offset += 1;

       C3 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_adc_cw, *cc_conf_c3 , tvb,offset, 1, ENC_BIG_ENDIAN);

       append_text_item = proto_tree_add_item(hpsdr_u_tree_cc_adc_cw, hf_hpsdr_u_cc_cw_keyer_speed, tvb,offset, 1, C3);
       proto_item_append_text(append_text_item," WPM");

       proto_tree_add_item(hpsdr_u_tree_cc_adc_cw, hf_hpsdr_u_cc_cw_keyer_mode, tvb,offset, 1, C3);
       offset += 1;

       C4 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_adc_cw, *cc_conf_c4 , tvb,offset, 1, ENC_BIG_ENDIAN);

       proto_tree_add_item(hpsdr_u_tree_cc_adc_cw, hf_hpsdr_u_cc_cw_keyer_weight, tvb,offset, 1, C4);
       proto_tree_add_boolean(hpsdr_u_tree_cc_adc_cw, hf_hpsdr_u_cc_cw_keyer_spacing,tvb,offset, 1, C2);     
       offset += 1;

   } else if ( C0_masked == 0x18 ) { // Additional Mercury 1

       proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
           C0_masked, "C0 Type 0x%02X: Additional Mercury 1",C0_masked);
       offset += 4;

   } else if ( C0_masked == 0x1A ) { // Additional Mercury 2

       proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
                          C0_masked, "C0 Type 0x%02X: Additional Mercury 2",C0_masked);
       offset += 4;

   } else if ( C0_masked == 0x1C ) { // ADC RX Assignment

       cc_rx_adc_item = proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
                            C0_masked, "C0 Type 0x%02X: ADC RX Assignment",C0_masked);
       hpsdr_u_tree_cc_rx_adc = proto_item_add_subtree(cc_rx_adc_item, ett_hpsdr_u_cc_rx_adc);

       C1 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_rx_adc, *cc_conf_c1, tvb,offset, 1, ENC_BIG_ENDIAN);

       proto_tree_add_item(hpsdr_u_tree_cc_rx_adc, hf_hpsdr_u_cc_rx1_adc_assign, tvb,offset, 1, C1);
       proto_tree_add_item(hpsdr_u_tree_cc_rx_adc, hf_hpsdr_u_cc_rx2_adc_assign, tvb,offset, 1, C1);
       proto_tree_add_item(hpsdr_u_tree_cc_rx_adc, hf_hpsdr_u_cc_rx3_adc_assign, tvb,offset, 1, C1);
       proto_tree_add_item(hpsdr_u_tree_cc_rx_adc, hf_hpsdr_u_cc_rx4_adc_assign, tvb,offset, 1, C1);
       offset += 1;

       C2 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_rx_adc, hf_hpsdr_u_cc_ep2_c2_1c, tvb,offset, 1, ENC_BIG_ENDIAN);

       append_text_item = proto_tree_add_item(hpsdr_u_tree_cc_rx_adc, hf_hpsdr_u_cc_rx5_adc_assign, tvb,offset, 1, C2);
       proto_item_append_text(append_text_item," :On TX ADC5 assigned to TX DAC");

       proto_tree_add_item(hpsdr_u_tree_cc_rx_adc, hf_hpsdr_u_cc_rx6_adc_assign, tvb,offset, 1, C2);
       proto_tree_add_item(hpsdr_u_tree_cc_rx_adc, hf_hpsdr_u_cc_rx7_adc_assign, tvb,offset, 1, C2);
       offset += 1;

       append_text_item = proto_tree_add_item(hpsdr_u_tree_cc_rx_adc, hf_hpsdr_u_cc_adc_input_atten_tx, tvb,offset, 1, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," dB"); 

       //C4 not used
       offset += 2;    

   } else if ( C0_masked == 0x1E ) { // CW Configuration 2

       cc_cw1_item = proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
                         C0_masked, "C0 Type 0x%02X: CW Configuration 2",C0_masked);
       hpsdr_u_tree_cc_cw1 = proto_item_add_subtree(cc_cw1_item, ett_hpsdr_u_cc_cw1);

       C1 = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(hpsdr_u_tree_cc_cw1, hf_hpsdr_u_cc_cw_source,tvb,offset, 1, C1);
       offset += 1;      
 
       proto_tree_add_item(hpsdr_u_tree_cc_cw1, hf_hpsdr_u_cc_cw_sidetone_vol,tvb,offset, 1, ENC_BIG_ENDIAN);
       offset += 1; 

       append_text_item = proto_tree_add_item(hpsdr_u_tree_cc_cw1, hf_hpsdr_u_cc_cw_ptt_delay, tvb,offset, 1, ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," mS"); 

       //C4 not used
       offset += 2;  

   } else if ( C0_masked == 0x20 ) { // CW Configuration 3

       cc_cw2_item = proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
                         C0_masked, "C0 Type 0x%02X: CW Configuration 3",C0_masked);
       hpsdr_u_tree_cc_cw2 = proto_item_add_subtree(cc_cw2_item, ett_hpsdr_u_cc_cw2);

       C1 = tvb_get_guint8(tvb, offset);
       high_byte = ( C1 << 2 ); //Shift Left 2 to make move for lower bits
       offset += 1;

       C2 = tvb_get_guint8(tvb, offset);
       C2 = ( (C2 << 6) >> 6 ); // Shift Left 6 then Shift Right 6 to get the 2 lowest bits

       final_byte = (high_byte + C2) - 10 ;

       append_text_item = proto_tree_add_uint(hpsdr_u_tree_cc_cw2, hf_hpsdr_u_cc_cw_hang_time,tvb,offset-1, 2, final_byte);
       proto_item_append_text(append_text_item," mS - Calculated, not on wire value.");
       offset += 1;    

       C3 = tvb_get_guint8(tvb, offset);
       high_byte = ( C3 << 4 ); //Shift Left 4 to make move for lower bits
       offset += 1; 

       C4 = tvb_get_guint8(tvb, offset);
       C4 = ( (C4 << 4) >> 4 ); // Shift Left 4 then Shift Right 4 to get the 3 lowest bits

       final_byte = high_byte + C4;
 
       append_text_item = proto_tree_add_uint(hpsdr_u_tree_cc_cw2, hf_hpsdr_u_cc_cw_sidetone_freq,tvb,offset-1, 2, final_byte);
       proto_item_append_text(append_text_item," Hz - Calculated, not on wire value.");
       offset += 1; 

   } else if ( C0_masked == 0x22 ) { // PWM Configuration

       cc_pwm_item = proto_tree_add_uint_format(tree, *cc_conf_sub, tvb, offset, 4,
                         C0_masked, "C0 Type 0x%02X: PWM Configuration",C0_masked);
       hpsdr_u_tree_cc_pwm = proto_item_add_subtree(cc_pwm_item, ett_hpsdr_u_cc_pwm);

       C1 = tvb_get_guint8(tvb, offset);
       high_byte = ( C1 << 2 ); //Shift Left 2 to make move for lower bits
       offset += 1;

       C2 = tvb_get_guint8(tvb, offset);
       C2 = ( (C2 << 6) >> 6 ); // Shift Left 6 then Shift Right 6 to get the 2 lowest bits

       final_byte = (high_byte + C2);

       append_text_item = proto_tree_add_uint(hpsdr_u_tree_cc_pwm, hf_hpsdr_u_cc_pwm_min,tvb,offset-1, 2, final_byte);
       proto_item_append_text(append_text_item," - Calculated, not on wire value.");
       offset += 1;   

       C3 = tvb_get_guint8(tvb, offset);
       high_byte = ( C3 << 2 ); //Shift Left 2 to make move for lower bits
       offset += 1;

       C4 = tvb_get_guint8(tvb, offset);
       C4 = ( (C4 << 6) >> 6 ); // Shift Left 6 then Shift Right 6 to get the 2 lowest bits

       final_byte = (high_byte + C4);

       append_text_item = proto_tree_add_uint(hpsdr_u_tree_cc_pwm, hf_hpsdr_u_cc_pwm_max,tvb,offset-1, 2, final_byte);
       proto_item_append_text(append_text_item," - Calculated, not on wire value.");
       offset += 1; 

   }

   ep2_data_item = proto_tree_add_uint_format(tree, *ep2_data_sub, tvb, offset, 504,
                       ENC_BIG_ENDIAN, "Left Right Audio Samples and IQ Samples (504 Bytes)");
   hpsdr_u_tree_ep2_data = proto_item_add_subtree(ep2_data_item, *ett_ep2_data);


   for (x=0; x<= 62; x++) {
        proto_tree_add_uint_format(hpsdr_u_tree_ep2_data,hf_hpsdr_u_ep2_idx, tvb, offset, 0,x,"Index: %d",x);
     
        L = tvb_get_guint16(tvb, offset,2);
        proto_tree_add_uint(hpsdr_u_tree_ep2_data, hf_hpsdr_u_ep2_l, tvb,offset, 2, L);
        offset += 2;

        R = tvb_get_guint16(tvb, offset,2);
        proto_tree_add_uint(hpsdr_u_tree_ep2_data, hf_hpsdr_u_ep2_r, tvb,offset, 2, R);
        offset += 2;

        I = tvb_get_guint16(tvb, offset,2);
        proto_tree_add_uint(hpsdr_u_tree_ep2_data, hf_hpsdr_u_ep2_i, tvb,offset, 2, I);
        offset += 2;

        Q = tvb_get_guint16(tvb, offset,2);
        proto_tree_add_uint(hpsdr_u_tree_ep2_data, hf_hpsdr_u_ep2_q, tvb,offset, 2, Q);
        offset += 2;

   }

   return offset;

}

static int hpsdr_usb_ep6_frame(proto_tree *tree, tvbuff_t *tvb, int offset, int frame_num) {

   //Submenu Items
   proto_item *c0_item = NULL;
   proto_item *cc_info_item = NULL;
   proto_item *cc_fp_item = NULL;
   proto_item *cc_rp_item = NULL;
   proto_item *cc_ps_item = NULL;
   proto_item *cc_ov_item = NULL;
   proto_item *ep6_data_item = NULL;

   proto_item *append_text_item = NULL;

   proto_tree *hpsdr_u_tree_c0 = NULL;
   proto_tree *hpsdr_u_tree_cc_info = NULL;
   proto_tree *hpsdr_u_tree_cc_fp = NULL;
   proto_tree *hpsdr_u_tree_cc_rp = NULL;
   proto_tree *hpsdr_u_tree_cc_ps = NULL;
   proto_tree *hpsdr_u_tree_cc_ov = NULL; 
   proto_tree *hpsdr_u_tree_ep6_data = NULL;

   guint8 C0 = -1;
   guint8 C0_masked = -1;
   guint8 C1 = -1;
   guint8 C2 = -1;
   guint8 C3 = -1;
   guint8 C4 = -1;
   guint8 value = -1;

   guint16 raw_bytes = -1;
   guint32 I = -1;
   guint32 Q = -1;
   guint16 ML = -1;

   int *sync = NULL;
   int *c0_sub = NULL;
   int *u_c0 = NULL;
   int *c0_ptt = NULL;
   int *c0_dash = NULL;
   int *c0_dot = NULL;
   int *c0_type = NULL;
   int *ep6_data = NULL;
   int *ett_ep6_data = NULL;
   int *ep6_data_sub = NULL;
   int *num_of_rx = NULL;

   int x = -1;
   int z = -1;

   int samp_num = -1;
   int pad = -1; 
   int adc_cal_offset =-1;  

   double power_f = -1;
   double result = -1;

   float bridge_volt = -1;
   float refvoltage = -1;
   float volts = -1;
   float watts = -1;
  
   const char *placehold = NULL ;

   switch ( frame_num ) {
 
       case 1:  
              sync = &hf_hpsdr_u_sync_1;
              c0_sub = &hf_hpsdr_u_c0_sub_1;
              u_c0 = &hf_hpsdr_u_c0_1;
              c0_ptt = &hf_hpsdr_u_c0_ptt_1;
              c0_dash = &hf_hpsdr_u_c0_dash_1;
              c0_dot = &hf_hpsdr_u_c0_dot_1;
              c0_type = &hf_hpsdr_u_c0_type_1;
              ett_ep6_data = &ett_hpsdr_u_ep6_data_1;
              ep6_data_sub = &hf_hpsdr_u_ep6_data_sub_1;
              ep6_data = &hf_hpsdr_u_ep6_data_1;
              num_of_rx = &hf_hpsdr_u_ep6_num_of_rx_1;
              break;

       case 2:  
              sync = &hf_hpsdr_u_sync_2;
              c0_sub = &hf_hpsdr_u_c0_sub_2;
              u_c0 = &hf_hpsdr_u_c0_2;
              c0_ptt = &hf_hpsdr_u_c0_ptt_2;
              c0_dash = &hf_hpsdr_u_c0_dash_2;
              c0_dot = &hf_hpsdr_u_c0_dot_2;
              c0_type = &hf_hpsdr_u_c0_type_2;
              ett_ep6_data = &ett_hpsdr_u_ep6_data_2;
              ep6_data_sub = &hf_hpsdr_u_ep6_data_sub_2;
              ep6_data = &hf_hpsdr_u_ep6_data_2;
              num_of_rx = &hf_hpsdr_u_ep6_num_of_rx_2;      
              break;
   }


   proto_tree_add_item(tree, *sync, tvb,offset, 3, ENC_BIG_ENDIAN);
   offset += 3;
 
   C0 = tvb_get_guint8(tvb, offset);
   c0_item = proto_tree_add_uint_format(tree, *c0_sub, tvb, offset, 1,
                 C0, "C&C Byte 0  : 0x%02X",C0 );
               
   hpsdr_u_tree_c0 = proto_item_add_subtree(c0_item, ett_hpsdr_u_c0);

   proto_tree_add_item(hpsdr_u_tree_c0, *u_c0, tvb,offset, 1, ENC_BIG_ENDIAN);
   //C0_masked = ( C0 & 0b11111000 ) ; // bitwise and
   C0_masked = ( C0 & 0xF8 ) ;

   proto_tree_add_boolean(hpsdr_u_tree_c0, *c0_ptt, tvb,offset, 1, C0);
   proto_tree_add_boolean(hpsdr_u_tree_c0, *c0_dash, tvb,offset, 1, C0);
   proto_tree_add_boolean(hpsdr_u_tree_c0, *c0_dot, tvb,offset, 1, C0);              
   append_text_item = proto_tree_add_boolean(hpsdr_u_tree_c0, *c0_type, tvb,offset, 1, C0 );
   proto_item_append_text(append_text_item," 0x%02X", C0_masked);
   offset += 1;

       // SDR Info 0
      // Foward Power 08
     // Reverse Power 10
    // Power Supply 18
   // ADC Overflow 20
   if ( C0_masked == 0x0 ) {  // SDR Info 0

       cc_info_item = proto_tree_add_uint_format(tree, hf_hpsdr_u_cc_info_sub, tvb, offset, 4,
                          C0_masked, "C0 Type 0x%02X: SDR Info",C0_masked);
       hpsdr_u_tree_cc_info = proto_item_add_subtree(cc_info_item, ett_hpsdr_u_cc_info);

       C1 = tvb_get_guint8(tvb, offset);
       proto_tree_add_item(hpsdr_u_tree_cc_info, hf_hpsdr_u_cc_info_c1, tvb,offset, 1, ENC_BIG_ENDIAN);

       proto_tree_add_boolean(hpsdr_u_tree_cc_info, hf_hpsdr_u_cc_info_adc_overflow, tvb,offset, 1, C1);
       proto_tree_add_boolean(hpsdr_u_tree_cc_info, hf_hpsdr_u_cc_info_i01, tvb,offset, 1, C1);
       proto_tree_add_boolean(hpsdr_u_tree_cc_info, hf_hpsdr_u_cc_info_i02, tvb,offset, 1, C1);
       proto_tree_add_boolean(hpsdr_u_tree_cc_info, hf_hpsdr_u_cc_info_i03, tvb,offset, 1, C1);
       proto_tree_add_boolean(hpsdr_u_tree_cc_info, hf_hpsdr_u_cc_info_i04, tvb,offset, 1, C1);
       proto_tree_add_boolean(hpsdr_u_tree_cc_info, hf_hpsdr_u_cc_info_cyclops_pll, tvb,offset, 1, C1);
       proto_tree_add_boolean(hpsdr_u_tree_cc_info, hf_hpsdr_u_cc_info_freq_chg, tvb,offset, 1, C1);
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_uint_format(hpsdr_u_tree_cc_info, hf_hpsdr_u_cc_info_mercury, tvb,offset, 1,value,
          "Mercury Software Version         : %d.%.1d",(value/10),(value%10));
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_uint_format(hpsdr_u_tree_cc_info, hf_hpsdr_u_cc_info_penelope, tvb,offset, 1,value,
          "Penelope Software Version        : %d.%.1d",(value/10),(value%10));
       offset += 1;

       value = tvb_get_guint8(tvb, offset);
       proto_tree_add_uint_format(hpsdr_u_tree_cc_info, hf_hpsdr_u_cc_info_penelope, tvb,offset, 1,value,
          "Interface Device Software Version: %d.%.1d  :Ozy/Magister, Metis, Hermes, etc.",(value/10),(value%10));
       offset += 1;

   } else if ( C0_masked == 0x08 ) {  // Foward Power 08

       cc_fp_item = proto_tree_add_uint_format(tree, hf_hpsdr_u_cc_fwdpw_sub, tvb, offset, 4,
                        C0_masked, "C0 Type 0x%02X: Forward Power",C0_masked );
       hpsdr_u_tree_cc_fp = proto_item_add_subtree(cc_fp_item, ett_hpsdr_u_cc_fp);

       raw_bytes = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);

       // Math from OpenHPSDR PowerSDR - console.cs
       // Bill Tracey (KD5TFD) - Doug Wigley (W5WC) - Warren Pratt (NR0V)
       power_f = (double)raw_bytes;
       result = 0.0;

       if (raw_bytes <= 2095)
       {
           if (raw_bytes <= 874)
           {
               if (raw_bytes <= 98)
               {
                   result = 0.0;
               }
               else  // > 98 
               {
                   result = (power_f - 98.0) * 0.065703;
               }
           }
           else  // > 874 
           {
               if (raw_bytes <= 1380)
               {
                   result = 50.0 + ((power_f - 874.0) * 0.098814);
               }
               else  // > 1380 
               {
                   result = 100.0 + ((power_f - 1380.0) * 0.13986);
               }
            }
       }
       else  // > 2095 
       {
           if (raw_bytes <= 3038)
           {
               if (raw_bytes <= 2615)
               {
                   result = 200.0 + ((power_f - 2095.0) * 0.192308);
               }
               else  // > 2615, <3038 
               {
                   result = 300.0 + ((power_f - 2615.0) * 0.236407);
               }
           }
           else  // > 3038 
           {
               result = 400.0 + ((power_f - 3038.0) * 0.243902);
           }
       }

       proto_tree_add_uint_format(hpsdr_u_tree_cc_fp, hf_hpsdr_u_cc_fwdpw_tx,tvb,offset, 2, result,
           "SDR TX RF Drive Power                       - ADC: %d  Watts: %f mW",raw_bytes,result);

       proto_tree_add_item(hpsdr_u_tree_cc_fp, hf_hpsdr_u_cc_fwdpw_tx,tvb,offset, 2,ENC_BIG_ENDIAN);
       offset += 2;

       proto_tree_add_item(hpsdr_u_tree_cc_fp, hf_hpsdr_u_cc_fwdpw_ant_pre,tvb,offset, 2,ENC_BIG_ENDIAN);   

       raw_bytes = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN); 
       volts = 0;
       watts = 0;
       // Math from OpenHPSDR PowerSDR - console.cs 
       // Bill Tracey (KD5TFD) - Doug Wigley (W5WC) - Warren Pratt (NR0V)
       bridge_volt = 0.09f;
       refvoltage = 3.3f;

       volts = (float)( raw_bytes / 4095.0f * refvoltage);
       if (volts != 0 ) { watts = (float)(pow(volts,2) / bridge_volt); }

       proto_tree_add_uint_format(hpsdr_u_tree_cc_fp, hf_hpsdr_u_cc_fwdpw_ant_pre,tvb,offset, 2, watts,
           "SDR TX Power From Anntena Preselector       - ADC: %d  Volts: %f  Watts: %f",raw_bytes,volts,watts);
       offset += 2;

   } else if ( C0_masked == 0x10) {  // Reverse Power 10

       cc_rp_item = proto_tree_add_uint_format(tree, hf_hpsdr_u_cc_revpwd_sub, tvb, offset, 4,
                        C0_masked, "C0 Type 0x%02X: Reverse Power",C0_masked );
       hpsdr_u_tree_cc_rp = proto_item_add_subtree(cc_rp_item, ett_hpsdr_u_cc_rp);
       
       raw_bytes = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
       volts = 0;
       watts = 0;
       // Math from OpenHPSDR PowerSDR - console.cs 
       // Bill Tracey (KD5TFD) - Doug Wigley (W5WC) - Warren Pratt (NR0V)
       bridge_volt = 0.09f;
       refvoltage = 3.3f;
       adc_cal_offset = 10; 
       if (raw_bytes < adc_cal_offset) { raw_bytes = adc_cal_offset = 0; }  
       volts = (float)((raw_bytes - adc_cal_offset) / 4095.0 * refvoltage);
       if (volts != 0 ) { watts = (float)pow(volts,2) / bridge_volt; }   

       proto_tree_add_uint_format(hpsdr_u_tree_cc_rp, hf_hpsdr_u_cc_revpwd_rev,tvb,offset, 2, watts,
           "SDR Reverse Power From Anntena Preselector - ADC: %d  Volts: %f  Watts: %f",raw_bytes,volts,watts);

       proto_tree_add_item(hpsdr_u_tree_cc_rp, hf_hpsdr_u_cc_revpwd_rev, tvb,offset, 2, ENC_BIG_ENDIAN);

       offset += 2;

       proto_tree_add_item(hpsdr_u_tree_cc_rp, hf_hpsdr_u_cc_revpwd_ain3, tvb,offset, 2, ENC_BIG_ENDIAN);
       offset += 2;

   } else if ( C0_masked == 0x18) {  // Power Supply 18

       cc_ps_item = proto_tree_add_uint_format(tree, hf_hpsdr_u_cc_pwsupp_sub, tvb, offset, 4,
                        C0_masked, "C0 Type 0x%02X: Power Supply",C0_masked );
       hpsdr_u_tree_cc_ps = proto_item_add_subtree(cc_ps_item, ett_hpsdr_u_cc_ps);

       proto_tree_add_item(hpsdr_u_tree_cc_ps, hf_hpsdr_u_cc_pwsupp_ain4, tvb,offset, 2, ENC_BIG_ENDIAN);
       offset += 2;

       proto_tree_add_item(hpsdr_u_tree_cc_ps, hf_hpsdr_u_cc_pwsupp_vol, tvb,offset, 2, ENC_BIG_ENDIAN);
 
       raw_bytes = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN); 

       // Math from OpenHPSDR PowerSDR - console.cs 
       // Bill Tracey (KD5TFD) - Doug Wigley (W5WC) - Warren Pratt (NR0V)
       volts = ( ((float)raw_bytes/ 4095) * 3.3f ) * ((4.7f + 0.82f) / 0.82f);

       append_text_item = proto_tree_add_uint_format(hpsdr_u_tree_cc_ps, hf_hpsdr_u_cc_pwsupp_vol,tvb,offset, 2, volts,
           "SDR (Hermes) Power Supply Value: %f",volts);
       proto_item_append_text(append_text_item," Volts - Calculated, not on wire value.");

       offset += 2;


   } else if ( C0_masked == 0x20) {  // ADC Overflow 20

       cc_ov_item = proto_tree_add_uint_format(tree, hf_hpsdr_u_cc_overflow_sub, tvb, offset, 4,
                        C0_masked, "C0 Type 0x%02X: ADC Overflow",C0_masked );
       hpsdr_u_tree_cc_ov = proto_item_add_subtree(cc_ov_item, ett_hpsdr_u_cc_ov);

       C1 = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(hpsdr_u_tree_cc_ov, hf_hpsdr_u_cc_overflow_adc1, tvb,offset, 1, C1);

       proto_tree_add_item(hpsdr_u_tree_cc_ov, hf_hpsdr_u_cc_overflow_mercury1, tvb,offset, 1, ENC_BIG_ENDIAN);
       offset += 1;

       C2 = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(hpsdr_u_tree_cc_ov, hf_hpsdr_u_cc_overflow_adc2, tvb,offset, 1, C2);

       proto_tree_add_item(hpsdr_u_tree_cc_ov, hf_hpsdr_u_cc_overflow_mercury2, tvb,offset, 1, ENC_BIG_ENDIAN);
       offset += 1;

       C3 = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(hpsdr_u_tree_cc_ov, hf_hpsdr_u_cc_overflow_adc3, tvb,offset, 1, C3);

       proto_tree_add_item(hpsdr_u_tree_cc_ov, hf_hpsdr_u_cc_overflow_mercury3, tvb,offset, 1, ENC_BIG_ENDIAN);
       offset += 1;

       C4 = tvb_get_guint8(tvb, offset);
       proto_tree_add_boolean(hpsdr_u_tree_cc_ov, hf_hpsdr_u_cc_overflow_adc4, tvb,offset, 1, C4);

       proto_tree_add_item(hpsdr_u_tree_cc_ov, hf_hpsdr_u_cc_overflow_mercury4, tvb,offset, 1, ENC_BIG_ENDIAN);
       offset += 1;
            
   }

     // 0
    // 1
   // more then 1             
   if ( rx_num == 0 ) {              
       append_text_item = proto_tree_add_item(tree, *ep6_data, tvb,offset, 504,
                              ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item,": IQ Samples and Mic/Line Samples (504 Bytes)");

       offset += 504;

   } else if (rx_num == 1) {
  
       ep6_data_item = proto_tree_add_uint_format(tree, *ep6_data_sub, tvb, offset, 504,ENC_BIG_ENDIAN, 
                          "IQ Samples and Mic/Line Samples (504 Bytes)");
       hpsdr_u_tree_ep6_data = proto_item_add_subtree(ep6_data_item, *ett_ep6_data);

       proto_tree_add_uint_format(hpsdr_u_tree_ep6_data,*num_of_rx,tvb,offset, 0, rx_num,
          "Number of Receivers: %d",rx_num);

       for (x=1 ; x<= 63; x++) {
           proto_tree_add_uint_format(hpsdr_u_tree_ep6_data,hf_hpsdr_u_ep6_idx, tvb, offset, 0,x,"Index: %d",x);
     
           I = tvb_get_guint24(tvb, offset,3); 
           proto_tree_add_uint(hpsdr_u_tree_ep6_data, hf_hpsdr_u_ep6_i, tvb,offset, 3, I);
           offset += 3;

           Q = tvb_get_guint24(tvb, offset,3); 
           proto_tree_add_uint(hpsdr_u_tree_ep6_data, hf_hpsdr_u_ep6_q, tvb,offset, 3, Q);
           offset += 3;

           ML = tvb_get_guint16(tvb, offset,2);  
           proto_tree_add_uint(hpsdr_u_tree_ep6_data, hf_hpsdr_u_ep6_ml, tvb,offset, 2, ML);
           offset += 2;

       }

   } else if (rx_num > 1) {

       samp_num = ( 504 / ((rx_num * 6) + 2) );
       pad = ( 504 % ((rx_num * 6) + 2) );

       ep6_data_item = proto_tree_add_uint_format(tree, *ep6_data_sub, tvb, offset, 504,ENC_BIG_ENDIAN, 
                          "IQ Samples and Mic/Line Samples (504 Bytes)");
       hpsdr_u_tree_ep6_data = proto_item_add_subtree(ep6_data_item, *ett_ep6_data);


       proto_tree_add_uint_format(hpsdr_u_tree_ep6_data,*num_of_rx,tvb,offset, 0, rx_num,
          "Number of Receivers: %d - Number of Samples: %d - Pad Bytes: %d",rx_num,samp_num,pad);
      
       for (x=1; x<= samp_num; x++) {
           proto_tree_add_uint_format(hpsdr_u_tree_ep6_data,hf_hpsdr_u_ep6_idx, tvb, offset, 0,x,"Index: %d",x);

           for ( z=1 ; z <= rx_num; z++) { 
               proto_tree_add_uint_format(hpsdr_u_tree_ep6_data,hf_hpsdr_u_ep6_rx_idx, tvb, offset, 0,z,"RX: %d",z); 
     
               I = tvb_get_guint24(tvb, offset,3);               
               proto_tree_add_uint(hpsdr_u_tree_ep6_data, hf_hpsdr_u_ep6_i, tvb,offset, 3, I);
               offset += 3;

               Q = tvb_get_guint24(tvb, offset,3); 
               proto_tree_add_uint(hpsdr_u_tree_ep6_data, hf_hpsdr_u_ep6_q, tvb,offset, 3, Q);
               offset += 3;
           }

           proto_tree_add_string_format(hpsdr_u_tree_ep6_data, hf_hpsdr_u_ep6_data_string_ml, tvb, offset, 0, placehold,
              "MIC/Line");

           ML = tvb_get_guint16(tvb, offset,2);  
           proto_tree_add_uint(hpsdr_u_tree_ep6_data, hf_hpsdr_u_ep6_ml, tvb,offset, 2, ML);

           proto_tree_add_string_format(hpsdr_u_tree_ep6_data, hf_hpsdr_u_ep6_data_string_end, tvb, offset, 0, placehold,
               "----------------------------------------------------------");
           offset += 2;

       }
       append_text_item = proto_tree_add_item(hpsdr_u_tree_ep6_data, hf_hpsdr_u_ep6_data_pad, tvb,offset, pad,   
                              ENC_BIG_ENDIAN);
       proto_item_append_text(append_text_item," (%d Bytes)",pad);
       offset += pad;
       
   }

   return offset;
}


static void dissect_hpsdr_u(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   gint offset = 0;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "HPSDR-USB");
   /* Clear out stuff in the info column */
   col_clear(pinfo->cinfo,COL_INFO);


   if (tree) { 
       proto_item *ti = NULL;
       proto_item *f1_item = NULL;
       proto_item *f2_item = NULL;

       proto_tree *hpsdr_u_tree = NULL;
       proto_tree *hpsdr_u_tree_f1 = NULL;
       proto_tree *hpsdr_u_tree_f2 = NULL;

       //proto_item *append_text_item = NULL;

       static guint8 status;
       static guint8 usb_end_point;

       static guint8 value = -1;
       static guint8 flags;
       static guint8 f1 = 1;
       static guint8 f2 = 2;

       int x = 0;

       const char *placehold = NULL ;

       const guint8 *discovery_ether_address;
       discovery_ether_address = tvb_get_ptr(tvb, 3, 6); // Has to be defined before using.

       ti = proto_tree_add_item(tree, proto_hpsdr_u, tvb, 0, -1, ENC_NA);
       hpsdr_u_tree = proto_item_add_subtree(ti, ett_hpsdr_u);
       proto_tree_add_item(hpsdr_u_tree, hf_hpsdr_u_id, tvb,offset, 2, ENC_BIG_ENDIAN);
       offset += 2; 
       proto_tree_add_item(hpsdr_u_tree, hf_hpsdr_u_status, tvb,offset, 1, ENC_BIG_ENDIAN); 

       status = tvb_get_guint8(tvb, offset);
       offset += 1;

       if ( status == 1 ) {  // Data TX
           proto_tree_add_item(hpsdr_u_tree, hf_hpsdr_u_end_point, tvb,offset, 1, ENC_BIG_ENDIAN);
           usb_end_point = tvb_get_guint8(tvb, offset);
           offset += 1;
           proto_tree_add_item(hpsdr_u_tree, hf_hpsdr_u_seq, tvb,offset, 4, ENC_BIG_ENDIAN);
           offset += 4;

           if ( usb_end_point == 6) { // HPSDR USB Frames to HOST

               // EP 6 Frame 1  
               f1_item = proto_tree_add_uint_format(hpsdr_u_tree, hf_hpsdr_u_ep_f1, tvb, offset, 512, f1,
                          "HPSDR USB EP6 Frame 1 (512 Bytes)");
               hpsdr_u_tree_f1 = proto_item_add_subtree(f1_item, ett_hpsdr_u_f1);

               offset = hpsdr_usb_ep6_frame(hpsdr_u_tree_f1, tvb, offset,1);	

               // EP 6 Frame 2  
               f2_item = proto_tree_add_uint_format(hpsdr_u_tree, hf_hpsdr_u_ep_f2, tvb, offset, 512, f2,
                          "HPSDR USB EP6 Frame 2 (512 Bytes)");
               hpsdr_u_tree_f2 = proto_item_add_subtree(f2_item, ett_hpsdr_u_f1);

               offset = hpsdr_usb_ep6_frame(hpsdr_u_tree_f2, tvb, offset,2);

           } else if ( usb_end_point == 4) { // Raw ADC Samples From SDR to Host

               proto_tree_add_uint_format(hpsdr_u_tree,hf_hpsdr_u_ep_f1, tvb,offset, 1024, f1,
                 "Assuming 512 by 16 bit samples."); 

               for ( x=0; x <= 511; x++) {
                   proto_tree_add_string_format(hpsdr_u_tree, hf_hpsdr_u_ep4_separator, tvb, offset, 0, placehold,
                      "-------------------------");

                   proto_tree_add_uint_format(hpsdr_u_tree, hf_hpsdr_u_ep4_sample_idx, tvb, offset, 0, x,
                     "Sample: %d",x); 

                   proto_tree_add_item(hpsdr_u_tree,hf_hpsdr_u_ep4_sample, tvb,offset, 2, ENC_BIG_ENDIAN);
                     offset += 2;

               }      


           } else if ( usb_end_point == 2) { // Host to SDR - HPSDR USB Frames
       
               // EP 2 Frame 1  
               f1_item = proto_tree_add_uint_format(hpsdr_u_tree, hf_hpsdr_u_ep_f1, tvb, offset, 512, f1,
                             "HPSDR USB EP2 Frame 1 (512 Bytes)");
               hpsdr_u_tree_f1 = proto_item_add_subtree(f1_item, ett_hpsdr_u_f1);
  
	       offset = hpsdr_usb_ep2_frame(hpsdr_u_tree_f1, tvb, pinfo, offset,1);

               // EP 2 Frame 2
               f2_item = proto_tree_add_uint_format(hpsdr_u_tree, hf_hpsdr_u_ep_f2, tvb, offset, 512, f2,
                             "HPSDR USB EP2 Frame 2 (512 Bytes)");
               hpsdr_u_tree_f2 = proto_item_add_subtree(f2_item, ett_hpsdr_u_f1);
  
	       offset = hpsdr_usb_ep2_frame(hpsdr_u_tree_f2, tvb, pinfo, offset,2);
           }

       } else if ( status == 2 ) { // Discovery

           if (pinfo->destport == HPSDR_U_PORT) {

               proto_tree_add_string_format(hpsdr_u_tree, hf_hpsdr_u_host_discover, tvb, offset, 0, placehold,
                 "Host Discovery Query");

	       offset = packet_end_pad(tvb,hpsdr_u_tree,offset,60);

           } else if (pinfo->srcport == HPSDR_U_PORT) {
            
               proto_tree_add_string_format(hpsdr_u_tree, hf_hpsdr_u_host_discover, tvb, offset, 1, placehold,
                 "Hardware Discovery Reply");	
               
	       proto_tree_add_ether(hpsdr_u_tree, hf_hpsdr_u_eth, tvb,offset, 6, discovery_ether_address);
               offset += 6;
 
	       value = tvb_get_guint8(tvb, offset);
   	       proto_tree_add_uint_format(hpsdr_u_tree,hf_hpsdr_u_ver,tvb,offset,1,value,
       		 "SDR Code Version: %d.%.1d",(value/10),(value%10));         
               offset += 1;

               proto_tree_add_item(hpsdr_u_tree, hf_hpsdr_u_bid, tvb,offset, 1, ENC_BIG_ENDIAN);
	       board_id = tvb_get_guint8(tvb, offset);
               offset += 1;

               if ( board_id == 0x06) { // Hermes_Lite
  		   proto_tree_add_item(hpsdr_u_tree, hf_hpsdr_u_hlite_ver, tvb,offset, 9, ENC_BIG_ENDIAN);
	           offset += 9;

		   offset = packet_end_pad(tvb,hpsdr_u_tree,offset,40);
               } 
	       
               else {
		   offset = packet_end_pad(tvb,hpsdr_u_tree,offset,49);
	       }

           }
	   

       } else if ( status == 3 ) { // not included:  Set IP - Program
           proto_tree_add_ether(hpsdr_u_tree, hf_hpsdr_u_setip_mac, tvb,offset, 6, discovery_ether_address);
           offset += 6;

           proto_tree_add_ipv4(hpsdr_u_tree, hf_hpsdr_u_setip_address, tvb,offset, 4,tvb_get_ipv4(tvb,offset));
           offset += 4; 

	   offset = packet_end_pad(tvb,hpsdr_u_tree,offset,8);

       } else if ( status == 4 ) { // Start - Stop

           flags = tvb_get_guint8(tvb, offset);  
           proto_tree_add_boolean(hpsdr_u_tree, hf_hpsdr_u_com_iq, tvb,offset, 1, flags);
           proto_tree_add_boolean(hpsdr_u_tree, hf_hpsdr_u_com_wb, tvb,offset, 1, flags);
           offset += 1;

	   offset = packet_end_pad(tvb,hpsdr_u_tree,offset,60);
       }
    
       check_length(tvb,pinfo,hpsdr_u_tree,offset);
   }


}

static gboolean
dissect_hpsdr_u_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

   // Heuristics test
   //- Used packet-smb.c for an example.
   // HPSDR USB over IP uses the same UDP port as the openHPSDR Ethernet protocol. 
   // Test the first two bytes for the USB over IP id.
   if ( tvb_get_guint16(tvb, 0,2) != 0xEFFE ) {
       return FALSE;
   }
  
   dissect_hpsdr_u(tvb, pinfo, tree);
   return TRUE;

}


void proto_reg_handoff_hpsdr_u(void)
{

    // register as heuristic dissector
    heur_dissector_add("udp", dissect_hpsdr_u_heur, "HPSDR USB Over IP",
                       "hpsdr_u_udp", proto_hpsdr_u, HEURISTIC_ENABLE);

}

