import pyshark

def CaptureLiveTrace():
    # Using pyShark to sniff from interface in real time within PyCharm
    capture = pyshark.LiveCapture(interface='WiFi', display_filter='')

    print("Starting Wireshark capture on interface {}...".format('WiFi'))
    try:
        for trace in capture.sniff_continuously(packet_count=10):
            print(trace)
    except KeyboardInterrupt:
        print("Wireshark capture stopped.")

def LaunchTrace():
    file_path = r"C:\Users\abdul\PycharmProjects\RDCandWiresharkAnaylsis\Traces\TraceToReview.pcap"

    #print("\nOpening Wireshark capture Trace from {}...\n".format(file_path))
    pcap = pyshark.FileCapture(file_path)
    print(pcap)

    return pcap

def LookupSIP(packet, attribute):
    attribute_value = packet.sip.get(attribute)
    mediaAttributes = [field.get_default_value() for field in packet.sip.sdp_media_attr.all_fields]
    print(mediaAttributes)
    #attribute_value =
    #print(attribute_value)
    return mediaAttributes

def PacketInfo(trace):

    for pkt in trace:
        if 'method' in pkt:
            media_layers = pkt['method'].get_multiple_layers()
            print(media_layers)
            for layer in media_layers:
                # Access attributes of each matching layer
                media_type = layer.media_type
                codec = layer.codec
                payload_type = layer.payload_type
                # Print or process attributes as needed
                print("Media Type:", media_type)
                print("Codec:", codec)
                print("Payload Type:", payload_type)

header = ['request_line', 'method', 'r_uri', 'r_uri_user', 'r_uri_host', 'r_uri_port', 'resend', 'msg_hdr', 'via', 'via_transport', 'via_sent_by_address', 'via_branch', 'via_sent_by_port', 'from', 'from_addr', 'from_host', 'from_port', 'from_param', 'from_tag', 'tag', 'to', 'to_display_info', 'display_info', 'to_addr', 'to_user', 'to_host', 'to_port', 'call_id', 'call_id_generated', 'cseq', 'cseq_seq', 'cseq_method', 'contact', 'contact_uri', 'contact_host', 'contact_port', 'content_type', 'content_length', 'msg_body', 'sdp_version', 'sdp_owner', 'sdp_owner_username', 'sdp_owner_sessionid', 'sdp_owner_version', 'sdp_owner_network_type', 'sdp_owner_address_type', 'sdp_owner_address', 'sdp_session_name', 'sdp_connection_info', 'sdp_connection_info_network_type', 'sdp_connection_info_address_type', 'sdp_connection_info_address', 'sdp_time', 'sdp_time_start', 'sdp_time_stop', 'sdp_media', 'sdp_media_media', 'sdp_media_port_string', 'sdp_media_port', 'sdp_media_proto', 'sdp_media_format', 'sdp_media_attr', 'sdp_media_attribute_field', 'sdp_mime_type', 'sdp_sample_rate']

def addDisplayFilter(pcap_file, display_filter):
    cap = pyshark.FileCapture(pcap_file)
    cap.apply_on_packets(lambda pkt: pkt.sniff_packet(display_filter=display_filter))
    for filteredTrace in cap:
        print(filteredTrace)
    return filteredTrace

def CaptureFilter(interface, capture_filter):
    cap = pyshark.LiveCapture(interface=interface, bpf_filter=capture_filter)

    for pkt in cap.sniff_continuously(packet_count=10):
        print(pkt) 
    return pkt


# def analyze_packet(pcap_file):
#     cap = pyshark.FileCapture(pcap_file)

#     for pkt in cap:
#         print("Packet number:", pkt.number)
#         print("Time:", pkt.sniff_timestamp)
#         print("Source IP:", pkt.ip.src)
#         print("Destination IP:", pkt.ip.dst)
#         print("Protocol:", pkt.transport_layer)

#         if hasattr(pkt, 'http'):
#             print("HTTP Request Method:", pkt.http.request_method)

#         if hasattr(pkt, 'dns'):
#             print("DNS Query:", pkt.dns.qry_name)


pcap = LaunchTrace()
pkt1 = pcap[0]
print(pkt1)

# for packet in pcap:
#     # Access the layers of the packet
#     layers = packet.layers
#
#     # Access multiple layers for each packet
#     for layer in layers:
#         # Print the layer type and its fields
#         print(f"Layer type: {layer.layer_name}")
#         for field in layer.field_names:
#             print(f"    {field}: {layer[field]}")
#
#     # Print a separator between packets
#     print("-" * 50)

LookupSIP(pkt1, "sdp_media_attr")
#PacketInfo(pcap)
# layer = pkt1.layers
# print(layer)



#print(pkt1.sip.get("expires"))


#print("sip" in pkt1)
#print(pkt1.sip.field_names)


