from scapy.all import *
import sys

def get_ip(domain: str):
    DNS_PORT = 53
    GOOGLE_IP = "8.8.8.8"

    try:
        dns_req = IP(dst=GOOGLE_IP) / UDP(dport=DNS_PORT) \
                  / DNS(rd=1, qd=DNSQR(qname=domain))

        ans = sr1(dns_req, verbose=0)

    except Exception:
        return None

    try:
        return ans["DNS"].an.rdata
    except AttributeError:
        return None

def main():
    # Bonus
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("Enter domain: ")
    addresses = get_ip(domain)

    if addresses is not None:
        print(f"Name: {domain}")
        print(f"Addresses: {addresses}")

    else:
        print(f"*** UnKnown can't find {domain}: Non-existent domain")

if __name__ == '__main__':
    main()
