from scapy.all import rdpcap, UDP
import struct
import numpy as np

def parse_vlp16_packet(payload):
    # VLP-16 packet: 42-byte header + 12 blocks (100 bytes each) + 6-byte footer = 1206 bytes
    if len(payload) != 1206:
        return f"Invalid packet length: {len(payload)} bytes, expected 1206"
    
    distances = []
    intensities = []
    azimuths = []
    
    # Parse 12 data blocks
    for block_idx in range(12):
        block_start = 42 + block_idx * 100
        if block_start + 100 > len(payload):
            print(f"Error: Block {block_idx} exceeds payload length {len(payload)}")
            continue
        
        # Azimuth (2 bytes, uint16, scaled by 0.01 to degrees)
        try:
            azimuth = struct.unpack('<H', payload[block_start:block_start+2])[0] / 100.0
            azimuths.append(azimuth)
        except struct.error as e:
            print(f"Error unpacking azimuth in block {block_idx}: {e}")
            continue
        
        # Parse 2 sequences of 16 lasers (48 bytes total per block)
        for seq in range(2):  # Two firing sequences
            for laser_id in range(16):  # 16 lasers per sequence
                data_start = block_start + 2 + (seq * 16 + laser_id) * 3
                if data_start + 3 > len(payload):
                    print(f"Error: Laser {laser_id} in block {block_idx}, sequence {seq} exceeds payload length")
                    continue
                
                try:
                    dist_raw = struct.unpack('<H', payload[data_start:data_start+2])[0]
                    dist = dist_raw * 0.002  # Scale to meters
                    intensity_raw = struct.unpack('<B', payload[data_start+2:data_start+3])[0]
                    intensity = intensity_raw / 255.0  # Normalize
                except struct.error as e:
                    print(f"Error unpacking laser {laser_id} in block {block_idx}, sequence {seq}: {e}")
                    continue
                
                # Filter plausible distances (VLP-16: 0.4m to 120m) and intensity > 0.1
                if 0.4 <= dist <= 120.0 and intensity > 0.1:
                    # VLP-16 vertical angles: -15° to +15°, 2° steps
                    vertical_angle = -15.0 + laser_id * 2.0
                    x = dist * np.cos(np.radians(vertical_angle)) * np.cos(np.radians(azimuth))
                    y = dist * np.cos(np.radians(vertical_angle)) * np.sin(np.radians(azimuth))
                    z = dist * np.sin(np.radians(vertical_angle))
                    distances.append(dist)
                    intensities.append(intensity)
                    print(f"Laser {laser_id}: Azimuth {azimuth:.2f}°, Distance {dist:.2f}m, Intensity {intensity:.2f}, (x,y,z): ({x:.2f}, {y:.2f}, {z:.2f})")
    
    # Summary statistics
    valid_count = len(distances)
    total_possible = 12 * 32  # 12 blocks * 2 sequences * 16 lasers
    azimuth_range = f"{min(azimuths):.2f}° to {max(azimuths):.2f}°" if azimuths else "N/A"
    intensity_mean = np.mean(intensities) if intensities else 0.0
    print(f"Valid distances: {valid_count}/{total_possible} ({valid_count/total_possible*100:.1f}%)")
    print(f"Azimuth range: {azimuth_range}")
    print(f"Average intensity: {intensity_mean:.2f}")
    return distances, intensities

# Load PCAP and parse first UDP packet
pcap = rdpcap('/home/george/nobackup/temp/velodyne-vlp16-1.pcapng')
for pkt in pcap:
    if UDP in pkt and pkt[UDP].dport == 2372:
        payload = bytes(pkt[UDP].payload)
        result = parse_vlp16_packet(payload)
        if isinstance(result, str):
            print(result)
        break