# Validates an IP address and determines its class.

# Args:
# - IP (str): The IP address to be validated.

# Returns:
# - Tuple: A tuple containing a boolean indicating if the IP is valid and a string denoting the IP class.

def ip_validation(ip):

    octets = ip.split(".")  #Splits the IP into its 4 octets

    if len(octets) != 4:    #Checks if there are exactly 4 octets
        return False, None

    for octet in octets:      ##Ensures each octet is a number
        if not octet.isdigit():
            return False, None
        num = int(octet)
        if num < 0 or num > 255:   #Ensures each octet is a number between 0 and 255
            return False, None

# Determining IP class based on the first octet.
# Determines the class of the IP based on the value of its first octet (Class A, B, C, D, or E)

    if 0 <= int(octets[0]) <= 127:
        return True, "A"
    elif 128 <= int(octets[0]) <= 191:
        return True, "B"
    elif 192 <= int(octets[0]) <= 223:
        return True, "C"
    elif 224 <= int(octets[0]) <= 239:
        return True, "D (Multicast Address Range), Not defined"
    elif 240 <= int(octets[0]) <= 255:
        return True, "E (Reserved Only), Not defined"
    else:
        return False, None

# Calculates the subnet mask and the number of possible subnets for a given IP class and CIDR.

# Args:
#  - ip_class: The class of the IP.
#  - cidr (optional): The CIDR value.

# Returns:
#  - tuple: A tuple containing the number of possible subnets and the subnet mask.

def calculate_subnet(ip_class, cidr=None):  #Purpose: Calculates the subnet mask and the number of possible subnets based on the IP's class and optionally provided CIDR

    if cidr:                          #If CIDR is provided, calculates the number of host bits by subtracting CIDR from 32 and then computes the possible subnets. Also, fetches the subnet mask corresponding to that CIDR
        host_bits = 32 - int(cidr)
        return 2 ** host_bits - 2, get_subnet_from_cidr(cidr)   #(2^host bits - 2)
    else:                             # If CIDR isn't provided, determines the possible subnets and default subnet mask based on the IP's class
        if ip_class == "A":     #Class A: By default, 8 bits are reserved for the network. The number of possible subnets is 2^(32-8) - 2 = 2^24 - 2
            return 2 ** (32 - 8) - 2, "255.0.0.0"
        elif ip_class == "B":    #Class B: 16 bits are reserved for the network. The number of possible subnets is 2^(32-16) - 2 = 2^16 - 2
            return 2 ** (32 - 16) - 2, "255.255.0.0"
        elif ip_class == "C":    #Class C: 24 bits are reserved. The number of possible subnets is 2^(32-24) - 2 = 2^8 - 2
            return 2 ** (32 - 24) - 2, "255.255.255.0"
        elif ip_class.startswith("D") or ip_class.startswith("E"):   #Class D and E: Not typically used for regular networking purposes
            return None, None

# Converts CIDR to its corresponding subnet mask.

# Args:
#  - cidr: The CIDR value.

# Returns:
#  - The subnet mask.

def get_subnet_from_cidr(cidr):   #Purpose: Converts a CIDR notation into its corresponding subnet mask

    total_bits = 32
    cidr = int(cidr)
    subnet_bits = ["1"] * cidr + ["0"] * (total_bits - cidr)    #Determines how many bits should be set to '1' based on the CIDR value and the remaining bits are set to '0'
    subnet_octets = [int("".join(subnet_bits[i:i+8]), 2) for i in range(0, total_bits, 8)]    #Converts each group of 8 bits to its decimal representation to form the subnet mask
    return ".".join(map(str, subnet_octets))


def get_cidr_from_subnets(num_subnets):

    bits_for_subnets = len(bin(num_subnets)) - 2
    total_bits = 32
    cidr = total_bits - bits_for_subnets

    return cidr

def get_cidr_from_hosts(num_hosts):

    total_bits = 32
    bits_for_hosts = len(bin(num_hosts + 2)) - 2  # +2 accounts for network and broadcast addresses
    cidr = total_bits - bits_for_hosts

    return cidr



# Main function to execute the program.
# Purpose: This is the main function that runs when the program is executed and display the menu
def main():

    print("------------------------------------------ ")    #Takes an IP address input from the user
    ip = input("Enter the IP address: ")
    print("------------------------------------------ ")
    valid, ip_class = ip_validation(ip)      #Validates the IP and fetches its class

    if not valid:
        print("***********************************************************")
        print("Invalid IP Address! Please enter valid IP xxx.xxx.xxx.xxx")
        print("***********************************************************")
        return

    print("1. Enter CIDR directly")
    print("---------------------------------------- ")
    print("2. Specify number of hosts")
    print("---------------------------------------- ")
    print("3. Specify number of subnets")
    
    choice = input("Enter your choice (1/2/3): ")


    if choice == "1":
        cidr = input("Enter CIDR: ")
        if not (0 <= int(cidr) <= 32):
            print("************************************")
            print("           Invalid CIDR !           ")
            print("************************************")
            return
    elif choice == "2":
        num_hosts = int(input("Enter number of hosts: "))
        cidr = get_cidr_from_hosts(num_hosts)
    elif choice == "3":
        num_subnets = int(input("Enter number of subnets: "))
        cidr = get_cidr_from_subnets(num_subnets)
    else:
        print("Invalid choice!")
        return

    subnets, subnet_mask = calculate_subnet(ip_class, cidr)    #If CIDR is valid, computes and displays the subnet mask and the number of possible subnets
#If CIDR isn't provided, it defaults to the class of the IP to determine these values
    print("---------------------------------------- ")
    print(f"The IP Address is: {ip} of --> Class {ip_class}")
    print("---------------------------------------- ")
    print(f"Subnet Mask is: {subnet_mask}")
    print("---------------------------------------- ")
    print(f"Number of possible subnets: {subnets}")

main()
