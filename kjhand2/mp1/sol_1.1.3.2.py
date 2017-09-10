from sys import argv

input_file = argv[1]
output_file = argv[2]

with open(input_file) as f:
    message = f.read().strip()
    message = bytearray(message)
    
mask = 0x3FFFFFFF
write_out = 0

for byte in message:
    intermediate = ((byte ^ 0xCC) << 24) | ((byte ^ 0x33) << 16) | ((byte ^ 0xAA) << 8) | (byte ^ 0x55)
    write_out = (write_out & mask) + (intermediate & mask)
    #print(format(write_out, 'x'))
    
with open(output_file, "w") as f:
    f.write(format(write_out, 'x'))
print(format(write_out, 'x'))