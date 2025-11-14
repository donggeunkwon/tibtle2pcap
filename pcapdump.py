import struct
import time

PCAPH_MAGIC_NUM = 0xa1b2c3d4
PCAPH_VER_MAJOR = 2
PCAPH_VER_MINOR = 4
PCAPH_THISZONE  = 0
PCAPH_SIGFIGS   = 0
PCAPH_SNAPLEN   = 65535
DLT_PPI = 147
DOT11COMMON_TAG = 0o2
GPS_TAG = 30002

class PcapDumper:
    def __init__(self, datalink, savefile, ppi = False):
        """
        Creates a libpcap file using the specified datalink type.
        datalink: Integer
        savefile: output filename
        """
        self.ppi = ppi
        self.__fh = open(savefile, mode='wb')
        self.datalink = datalink
        # global pcap header (binary)
        self.__fh.write(b''.join([
            struct.pack("I", PCAPH_MAGIC_NUM),
            struct.pack("H", PCAPH_VER_MAJOR),
            struct.pack("H", PCAPH_VER_MINOR),
            struct.pack("I", PCAPH_THISZONE),
            struct.pack("I", PCAPH_SIGFIGS),
            struct.pack("I", PCAPH_SNAPLEN),
            struct.pack("I", DLT_PPI if self.ppi else self.datalink)
        ]))

    def pcap_dump(self, packet, ts_sec=None, ts_usec=None, orig_len=None,
                  freq_mhz=None, ant_dbm=None, location=None, dlt=None):
        """
        Appends a new packet to the libpcap file.
        packet: bytes (if given as str, it will be encoded using latin-1)
        location: (lon, lat, alt) tuple if provided
        """
        # ensure packet is bytes
        if isinstance(packet, str):
            packet = packet.encode('latin-1')

        # Build CACE PPI headers if requested
        if self.ppi is True:
            pph_len = 8  # base ppi header length

            # 802.11-common field length and defaults
            pph_len += 24  # 802.11-common header and data
            rf_freq_mhz = 0x0000 if freq_mhz is None else freq_mhz
            rf_ant_dbm = 0 if ant_dbm is None else ant_dbm

            caceppi_f80211common = b''.join([
                struct.pack("<H", DOT11COMMON_TAG),  # Field Type 802.11-Common
                struct.pack("<H", 20),               # length in bytes
                struct.pack("<Q", 0),                # FSF-Timer
                struct.pack("<H", 0),                # Flags
                struct.pack("<H", 0),                # Rate
                struct.pack("<H", rf_freq_mhz),      # Channel-Freq
                struct.pack("<H", 0x0080),           # Channel-Flags = 2GHz
                struct.pack("<B", 0),                # FHSS-Hopset
                struct.pack("<B", 0),                # FHSS-Pattern
                struct.pack("<b", rf_ant_dbm),       # dBm-Ansignal
                struct.pack("<b", 0)                 # dBm-Antnoise
            ])

            caceppi_fgeolocation = None
            if location is not None:
                pph_len += 20  # geolocation header and data length
                (lon, lat, alt) = location
                # Sanity checking on values of location data:
                if lat > -180.00000005 and lat < 180.00000005:
                    lat_i = int(round((lat + 180.0) * 1e7))
                else:
                    raise Exception("Latitude value is out of expected range: %.8f" % lat)
                if lon > -180.00000005 and lon < 180.00000005:
                    lon_i = int(round((lon + 180.0) * 1e7))
                else:
                    raise Exception("Longitude value is out of expected range: %.8f" % lon)
                if alt > -180000.00005 and alt < 180000.00005:
                    alt_i = int(round((alt + 180000.0) * 1e4))
                else:
                    raise Exception("Altitude value is out of expected range: %.8f" % alt)
                # Build Geolocation PPI Header
                caceppi_fgeolocation = b''.join([
                    struct.pack("<H", GPS_TAG),
                    struct.pack("<H", 20),
                    struct.pack("<B", 1),        # Geotag Version
                    struct.pack("<B", 2),        # Geotag Pad
                    struct.pack("<H", 24),       # Geotag Length
                    struct.pack("<I", 0x0E),     # GPS fields mask
                    struct.pack("<I", lat_i),    # GPS Latitude
                    struct.pack("<I", lon_i),    # GPS Longitude
                    struct.pack("<I", alt_i)     # GPS Altitude
                ])

            # CACE PPI Header
            caceppi_hdr = b''.join([
                struct.pack("<B", 0),               # PPH version
                struct.pack("<B", 0x00),            # PPH flags
                struct.pack("<H", pph_len),         # PPH len
                struct.pack("<I", self.datalink)    # Field (datalink)
            ])
        else:
            # if not using ppi, set these to None to avoid referenced before assignment
            caceppi_hdr = None
            caceppi_fgeolocation = None
            caceppi_f80211common = None

        # Timestamp default: use current time
        if ts_sec is None or ts_usec is None:
            now = time.time()
            ts_sec = int(now)
            ts_usec = int((now - ts_sec) * 1_000_000)

        plen = len(packet)
        if orig_len is None:
            orig_len = plen

        # Encapsulated packet header and packet (binary pieces)
        output_list = [
            struct.pack("I", ts_sec),
            struct.pack("I", ts_usec),
            struct.pack("I", orig_len),
            struct.pack("I", plen)
        ]

        if self.ppi is True:
            output_list[2] = struct.pack("I", orig_len + pph_len)
            output_list[3] = struct.pack("I", plen + pph_len)
            output_list.append(caceppi_hdr)
            if caceppi_fgeolocation is not None:
                output_list.append(caceppi_fgeolocation)
            output_list.append(caceppi_f80211common)
        if dlt:
            # assume dlt is bytes; if int, pack to 4 bytes
            if isinstance(dlt, int):
                output_list.append(struct.pack("I", dlt))
            else:
                # if it's str, convert to bytes safely
                if isinstance(dlt, str):
                    dlt = dlt.encode('latin-1')
                output_list.append(dlt)

        output_list.append(packet)

        # CRITICAL: join as bytes
        output = b''.join(output_list)

        self.__fh.write(output)
        # Specially for handling FIFO needs:
        try:
            self.__fh.flush()
        except IOError as e:
            raise e

        return

    def close(self):
        """
        Closes the output packet capture; wrapper for pcap_close().
        """
        self.pcap_close()

    def pcap_close(self):
        """
        Closed the output packet capture.
        """
        self.__fh.close()
