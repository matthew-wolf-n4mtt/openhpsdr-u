09-MAY-2019 Matthew J. Wolf <matthew.wolf.hpsdr@speciosus.net>

The OpenHPSDR-USB Plug-in for Wireshark is written to disassemble the 
OpenHPSDR USB frames over IP protocol. The protocol is also is 
referred to as "Protocol 1".

The protocol is definded in the documents and web page cited below.
 
[1] Harman, Phil. and Martin, Joe. HPSDR - USB Protocol V1.58. 2014. [Online]. 
    Available at: 
    https://github.com/TAPR/OpenHPSDR-SVN/blob/master/Documentation/USB_protocol_V1.58.doc 
    [Accessed: 3 May 2019]. 

[2] Harman, Phil. Metis - How it Works V1.33. 2015. [Online].
    Available at:
    https://github.com/TAPR/OpenHPSDR-SVN/blob/master/Metis/Documentation/Metis-%20How%20it%20works_V1.33.pdf
    [Accessed 3 May 2019].

[3] Softerhardware. “softerhardware/Hermes-Lite”. GitHub. [Online].
    Available: 
    https://github.com/softerhardware/Hermes-Lite/wiki/Protocol-Coverage
    [Accessed: 06-May-2019].

Version: 0.3.0
  - Wireshark version 3.0.1
  - Candidate for first release.  
  - Changed source name from "hpsdr_u" to "openhpsdr-u". New name is the same
     format as the OpenHPSDR Ethernet plug-in , openhpsdr-e.
  - Changed Heuristic dissector short_name from "hpsdr_u_udp" to "openhpsdr-u".
  - Added references for Protocol 1 to text strings.
    -- New Heuristic dissector display_name: "OpenHPSDR USB - P1 - USB in UDP"
    -- New Name: "OpenHPSDR USB Over IP - Protocol 1"
    -- New Short Name: "HPSDR-USB_P1"
    -- No change to Abbreviation: "hpsdr-u"
  - Added a preference to display the Hermes-Lite changes to Command and
    Control.

Version: 0.2.0
  - Wireshark version 2.2.3
  - Added disassembly of status 3 datagrams.
  - Added disassembly of USB end point 4 datagrams.
  - Added zero padding.
  - Added validation of the length of the datagrams.
  - Added protocol preferences to enable or disable some of the length testing.
  - Rewrote disassembly of Discovery and Start-Stop status.
  - Cleaned up formatting and field names in attempt to improve
    understandably.
  - The Plug-in should disassemble every thing that is included in the
    Protocol.

Version: 0.1.1
 - While waiting for SVN access I started to work on a plug-in for the OpenHPSDR
   Ethernet Protocol. Both the USB over IP and the Ethernet protocol use UDP
   port 1024. This means that the two plug-ins have to coexist with each other.
 - Changed the plug-in to registering as heuristic dissector. The plug-in tests
   the first two bytes of the UDP payload for the 0xEFFE id. Then it does not
   see the ID it exits.
 - I do not foresee any more updates until I finish the plug-in for the OpenHPSDR
   Ethernet Protocol.

Version: 0.1.0
 - There is no disassembly of status 3 datagrams. Status 3 is used to
   manually set the SDR's IP address and program the SDR's firmware.
 - There is no disassembly of USB end point 4 datagrams. USB end point 4 
   is used for sending raw ADC (Wide Band-scope) samples to the HOST. The 
   Wide Band-scope bit in the Start / Stop Command is disassembled. 

-------------------------------------------------------------------------------

General Notes
-------------

Only use the plug-in disassembly of the protocol as tool. Do not rely on it to
tell you exactly what is happening with the SDR or the host application. This 
plug-in calculates numbers for some objects. One example is the TX forward 
power. Only use the calculated number if you know for a fact that the SDR is 
truly transmitting. If the SDR is not transmitting and the plug-in reports a 
positive value for the forward power. Disregard the calculated power.


The disassembler in the plug-in attempts to identify which IQ bits belong to 
which receiver when there are multiple receivers. It will also identify the pad
bits. The disassembler only records the number of receivers when it believes the 
SDR is not sending IQ data. I had add this limitation because some of the host 
applications stop sending the correct number of receivers in the USB end point 2 
frames after it sends the start command to the SDR.

The disassembler believes the SDR is not sending IQ data when it first starts to 
disassemble the datagrams. If the disassembly is started after
the IQ start command is sent, the number of receivers in the USB end point 2 C&C 
C0=0x00 USB frame will be used for the number of receivers. This also means when
the host application does not report the correct number receivers. The 
disassembler will not be able to correctly identify which IQ bits go with which 
receivers.       

The disassembler will stop recording the number of receivers when it sees a IQ 
start command. It will not record number of receivers again until it sees a stop
command. This is a work round for host applications that stop reporting the 
correct number of receivers. The application has to tell the SDR the correct 
number of receivers before it sends the start command. After the start command, 
I assume the SDR does not need the application to report the correct number of 
receivers.

OK, if you do not care about the last paragraph. What you need to do with 
applications that do not all send the correct number of receivers is:
1. Start the packet capture before the host application sends the start command.
2. You need to make sure that you capture the USB end point 2 frame where the 
    host application tells the SDR then number of receivers right before it sends
    the IQ start command
3. Then make sure you capture the host application sending the start command.
4. More simply start the capture before for start the host application! 


There is one item I had to add for misbehaving host applications. Some 
applications send the first USB end point 2 frame late. They add extra empty 
bytes between the end of the sequence number and the start of the USB frame.
The disassembler searches for the first USB sync bytes. When the sync bytes are
not right after the sequence number the disassembler displays a warring that 
there are extra bits. Once the disassembler finds the sync bytes, it 
disassembles the USB frames.

Plug In Preferences
-------------------

There are three configurable preferences in the Wireshark dissector. 

They are all Boolean (on or off) preferences.

-"Strict Checking of Datagram Size"
  Disable checking for added bytes at the end of the datagrams.
  Turning off disables a warning message.

-"Strict Pad Checking"
  Strict checking of the amount of pad bytes at the end of the datagrams.
  When enabled, Wireshark (not the OpenHPSDR dissector) will display
  a "Malformed Packet" error for a datagram without the correct
  number of pad bytes. 
  When disabled, checking is only for one pad byte instead of checking
  for the correct number of pad bytes.

-"End Point 2 Sync Checking"  
  Some Host applications add extra bytes in front of the USB end point 2
  data. When disabled, there will be no checking for the insertion of extra 
  bytes.       

-"Hermes-Lite Command and Control"
  -- MOX repurposed as PTT.
  -- Random toggles RX ADC AGC.
  -- Dither toggles RX LNA gain.
  -- Input attenuator used for preamp.

Display Filters
---------------

In Wireshark you can filter packets by using display filters. The display 
filters use fields that are created when the packets are disassembled. I tried
to add fields for every thing in the protocol. A few examples are below.   

hpsdr-u.status == 0x04
-Display filter that will only display the start stop (status 4) datagrams.
 
hpsdr-u.cc.hpf_6-5 == 1 && hpsdr-u.cc.lpf_60-40 == 1
-A filter that will only display datagrams that tell the SDR hardware to enable
 the 6.5 MHZ HPF and the 60/40 meter LPF on Alex. 


The easiest way to find a field name is to click on a item in Wireshark. The 
field label will appear on the bottom of the Wireshark window. You can also 
click on the bytes in the raw display to get the field labels. When you do a
right mouse click on a field, the menu has a has build-in filter options. The 
menu has a "Copy" function that copies the field name to the clip board.
