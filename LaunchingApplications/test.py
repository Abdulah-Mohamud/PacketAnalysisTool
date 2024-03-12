import pyshark
from packaging import version

cap = pyshark.FileCapture('C:/Users/abdul/Downloads/TraceToReview.pcap')
pcap = cap[0]

dnse = [field.get_default_value() for field in pcap.sip.sdp_media_attr.all_fields]
print(dnse)

for pkt in cap:
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

def get_tshark_display_filter_flag(tshark_version):
    """Returns '-Y' for tshark versions >= 1.10.0 and '-R' for older versions."""
    if tshark_version >= version.parse("1.10.0"):
        return "-Y"
    else:
        return "-R"

def get_parameters(self, packet_count=None):
    """Returns the special tshark parameters to be used according to the configuration of this class."""
    params = []
    if self._capture_filter:
         params += ["-f", self._capture_filter]
    if self._display_filter:
        params += [get_tshark_display_filter_flag(self._get_tshark_version(),),
                    self._display_filter]
    # Raw is only enabled when JSON is also enabled.
    if self.include_raw:
        params += ["-x"]
    if packet_count:
        params += ["-c", str(packet_count)]

    if self._custom_parameters:
        if isinstance(self._custom_parameters, list):
            params += self._custom_parameters
        elif isinstance(self._custom_parameters, dict):
            for key, val in self._custom_parameters.items():
                params += [key, val]
        else:
            raise TypeError("Custom parameters type not supported.")

    if all(self.encryption):
        params += ["-o", "wlan.enable_decryption:TRUE", "-o", 'uat:80211_keys:"' + self.encryption[1] + '","' +
                                                                  self.encryption[0] + '"']
    if self._override_prefs:
        for preference_name, preference_value in self._override_prefs.items():
            if all(self.encryption) and preference_name in ("wlan.enable_decryption", "uat:80211_keys"):
                continue  # skip if override preferences also given via --encryption options
            params += ["-o", f"{preference_name}:{preference_value}"]

    if self._output_file:
        params += ["-w", self._output_file]

    if self._decode_as:
        for criterion, decode_as_proto in self._decode_as.items():
            params += ["-d",
                        ",".join([criterion.strip(), decode_as_proto.strip()])]

    if self._disable_protocol:
        params += ["--disable-protocol", self._disable_protocol.strip()]

    return params