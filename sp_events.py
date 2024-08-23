import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scapy.all import rdpcap, Ether, IP, TCP
from statsmodels.graphics.tsaplots import plot_acf
from numpy.fft import fft

def parse_dnp3_frame(payload):
    fields = {}
    
    if len(payload) > 0 and payload[:2] == b'\x05\x64':  # DNP3 Start bytes
        dnp3_control = payload[3]
        dnp3_app_control = payload[10]

        fields['DNP3 Control'] = hex(dnp3_control)
        fields['Application Control'] = hex(dnp3_app_control)
        fields['Unsolicited'] = bool(dnp3_app_control & 0x20)  
        fields['Function Code'] = payload[11]

        is_spontaneous = (dnp3_control & 0x0F == 0x04) and fields['Unsolicited']
        fields['Spontaneous'] = is_spontaneous

    return fields

def parse_iec104_frame(payload):
    fields = {}
    
    if len(payload) > 0 and payload[0] == 0x68:  # IEC 104 Start byte
        apdu_length = payload[1]
        if len(payload) >= apdu_length + 2:
            apci = payload[:6]  # APCI (Application Protocol Control Information)
            asdu = payload[6:6+apdu_length-4]  # ASDU (Application Service Data Unit)

            fields['APCI'] = apci.hex()
            fields['ASDU'] = asdu.hex()

            type_id = asdu[0]
            fields['Type ID'] = type_id

            is_spontaneous = type_id == 3  # Type ID 3 indicates M_SP_NA_1 (single-point information with quality descriptor)
            fields['Spontaneous'] = is_spontaneous

    return fields

def identify_goose_spontaneous_events(packet):
    if Ether in packet and packet[Ether].type == 0x88B8:
        return True
    return False

def parse_frame(frame):
    fields = {}

    if Ether in frame:
        eth = frame[Ether]
        fields['Source MAC'] = eth.src
        fields['Destination MAC'] = eth.dst

    if IP in frame:
        ip = frame[IP]
        fields['Source IP'] = ip.src
        fields['Destination IP'] = ip.dst
        fields['timestamp'] = frame.time

    if TCP in frame:
        tcp = frame[TCP]
        fields['Source Port'] = tcp.sport
        fields['Destination Port'] = tcp.dport

        payload = bytes(tcp.payload)

        dnp3_fields = parse_dnp3_frame(payload)
        if dnp3_fields:
            fields.update(dnp3_fields)
            return fields

        iec104_fields = parse_iec104_frame(payload)
        if iec104_fields:
            fields.update(iec104_fields)
            return fields

    # Checking for GOOSE protocol in Ethernet frames
    if identify_goose_spontaneous_events(frame):
        fields['GOOSE'] = True
        fields['Spontaneous'] = True
        fields['timestamp'] = frame.time
        return fields

    return fields

def analyze_protocol(protocol_data, protocol_name):
    if protocol_data.empty:
        print(f"No data available for {protocol_name}")
        return
    
    protocol_data = protocol_data.copy()
    protocol_data['inter_arrival_time'] = protocol_data['timestamp'].diff()

    if protocol_data['inter_arrival_time'].isnull().all():
        print(f"Not enough data to calculate inter-arrival times for {protocol_name}")
        return

    # Plot inter-arrival times
    plt.figure(figsize=(10, 6))
    plt.plot(protocol_data['timestamp'], protocol_data['inter_arrival_time'])
    plt.xlabel('Time')
    plt.ylabel('Inter-Arrival Time (s)')
    plt.title(f'Inter-Arrival Times of {protocol_name} Packets')
    plt.show()

    # Plot Autocorrelation
    plot_acf(protocol_data['inter_arrival_time'].dropna(), lags=50)
    plt.title(f'Autocorrelation of Inter-Arrival Times for {protocol_name}')
    plt.show()

    # Fourier Transform
    inter_arrival_times = protocol_data['inter_arrival_time'].dropna().values
    if len(inter_arrival_times) == 0:
        print(f"No valid inter-arrival times for {protocol_name}")
        return
    
    fft_result = fft(inter_arrival_times)
    frequencies = np.fft.fftfreq(len(fft_result))

    plt.figure(figsize=(10, 6))
    plt.plot(frequencies, np.abs(fft_result))
    plt.xlabel('Frequency (Hz)')
    plt.ylabel('Amplitude')
    plt.title(f'Frequency Spectrum of Inter-Arrival Times for {protocol_name}')
    plt.show()

def plot_spontaneous_events(dnp3_events, iec104_events, goose_events):
    plt.figure(figsize=(12, 8))

    bar_width = 0.2  # bar width 

    if not dnp3_events.empty:
        plt.bar(dnp3_events['timestamp'], np.ones(len(dnp3_events)), width=bar_width, color='blue', alpha=0.5, label='DNP3')
    if not iec104_events.empty:
        plt.bar(iec104_events['timestamp'], np.ones(len(iec104_events)), width=bar_width, color='green', alpha=0.5, label='IEC 104')
    if not goose_events.empty:
        plt.bar(goose_events['timestamp'], np.ones(len(goose_events)), width=bar_width, color='red', alpha=0.5, label='GOOSE')

    plt.xlabel('Time')
    plt.ylabel('Spontaneous Events')
    plt.title('Spontaneous Events Over Time')
    plt.legend()
    plt.show()

def plot_individual_protocol_events(protocol_events, protocol_name, color):
    plt.figure(figsize=(10, 6))
    bar_width = 0.2  # bar width 
    plt.bar(protocol_events['timestamp'], np.ones(len(protocol_events)), width=bar_width, color=color, alpha=0.5)
    plt.xlabel('Time')
    plt.ylabel('Spontaneous Events')
    plt.title(f'Spontaneous Events Over Time - {protocol_name}')
    plt.show()

# Load the PCAP file
pcap_file = 'HiWi/Datasets/QUT_DNP3/normal_00000_20160820095928.pcap'
packets = rdpcap(pcap_file)

# Parse each frame and filter for spontaneous events
parsed_packets = [parse_frame(packet) for packet in packets if TCP in packet or (Ether in packet and packet[Ether].type == 0x88b8)]

# Convert to DataFrame
df = pd.DataFrame(parsed_packets)

# Filter spontaneous events
dnp3_events = df[df['Spontaneous'] & df.get('DNP3 Control').notnull()].copy() if 'DNP3 Control' in df else pd.DataFrame()
iec104_events = df[df['Spontaneous'] & df.get('APCI').notnull()].copy() if 'APCI' in df else pd.DataFrame()
goose_events = df[df['Spontaneous'] & df.get('GOOSE').notnull()].copy() if 'GOOSE' in df else pd.DataFrame()

# Print the number of spontaneous events for each protocol
print(f"Number of DNP3 spontaneous events: {len(dnp3_events)}")
print(f"Number of IEC 104 spontaneous events: {len(iec104_events)}")
print(f"Number of GOOSE spontaneous events: {len(goose_events)}")

# Plot bar plot of spontaneous events
plot_spontaneous_events(dnp3_events, iec104_events, goose_events)

# Plot individual protocol events
if not dnp3_events.empty:
    plot_individual_protocol_events(dnp3_events, 'DNP3', 'blue')
else:
    print("No DNP3 spontaneous events found.")

if not iec104_events.empty:
    plot_individual_protocol_events(iec104_events, 'IEC 104', 'green')
else:
    print("No IEC 104 spontaneous events found.")

if not goose_events.empty:
    plot_individual_protocol_events(goose_events, 'GOOSE', 'red')
else:
    print("No GOOSE spontaneous events found.")

# Analyze DNP3 spontaneous events
analyze_protocol(dnp3_events, 'DNP3')

# Analyze IEC 104 spontaneous events
if not iec104_events.empty:
    analyze_protocol(iec104_events, 'IEC 104')
else:
    print("No IEC 104 spontaneous events found.")

# Analyze GOOSE spontaneous events
if not goose_events.empty:
    analyze_protocol(goose_events, 'GOOSE')
else:
    print("No GOOSE spontaneous events found.")
