#!/home/alexis/dev/bin/python3
# We'll extract and decode all the unique hex parts from the text file provided
# We got the file by executing strings on the .pcap file to only extract the dns address used in the dns protocol to exfiltrate the data
import re

# Load the file content
with open("./discret_tunneling.txt", "r") as file:
    text = file.read()

# Extract all hex values before the '!' character (as seen in the format like: HEX!domain)
hex_values = re.findall(r'([0-9a-fA-F]+)!', text)

# Deduplicate and sort by order of appearance (preserving potential transmission order)
seen = set()
ordered_hex = []
for val in hex_values:
    if val not in seen:
        seen.add(val)
        ordered_hex.append(val)

# Decode each hex value
decoded_lines = []
for hex_val in ordered_hex:
    try:
        decoded = bytes.fromhex(hex_val).decode('utf-8', errors='replace')
        decoded_lines.append(decoded)
    except Exception as e:
        decoded_lines.append(f"[ERROR: {e}]")

# Join all the decoded parts to reconstruct the full message
reconstructed_text = ''.join(decoded_lines)
reconstructed_text[:1000]  # Preview only the first 1000 characters

# Save the reconstructed text to a file
with open("decoded_output.txt", "w") as output_file:
    output_file.write(reconstructed_text)
