from scapy.all import *
import socket, sys

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

def pingMsg(domain: str, time_to_live: int):
    try:
        fullMsg = IP(dst=domain, ttl=time_to_live) / ICMP()

        ans = sr1(fullMsg, verbose=0, timeout=3)

    except (socket.gaierror, Exception):
        return None, None

    if ans is None:
        return None, None

    time = ans.time - fullMsg.sent_time

    # Convert to to ml
    time *= 1000

    time = round(time)

    return time, ans

def trace(domain: str):
    time_exceeded_code = 11

    ttl = 128
    ans: sr1

    for i in range(ttl):
        i += 1

        # Male ping to the domain with ttl of i
        time, ans = pingMsg(domain, time_to_live=i)

        # Get ip of the answering machine
        try:
            ip_answer = ans['IP'].src
        except TypeError:
            print(f"{i}  timeout")
            continue

        print(f"{i}  {time}   ms   {ip_answer}")

        if ans["ICMP"].type != time_exceeded_code:
            break


def main():
    # Args from cmd - Bonus
    if len(sys.argv) <= 1:
        domain = input("Enter domain: ")
    else:
        domain = sys.argv[1]

    domain_ip = get_ip(domain)

    # Domain is not reachable
    if domain_ip is None:
        print(f"Unable to resolve target system name {domain}.")
        return

    trace(domain)

    print("Trace complete.")

if __name__ == '__main__':
    main()
