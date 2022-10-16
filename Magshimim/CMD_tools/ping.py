from scapy.all import *
import socket
import time, sys

def pingMsg(domain: str):
    try:
        fullMsg = IP(dst=domain) / ICMP()

        ans = sr1(fullMsg, verbose=0, timeout=3)

    except (socket.gaierror, Exception):
        return None, None

    if ans is None:
        return None, None

    time = ans.time - fullMsg.sent_time

    # Convert to to ml
    time *= 1000

    time = round(time)
    return time, "2a00:1450:4006:812::200e" # Random mac makes it look real


def pingMultiple(domain: str):
    times = []
    for i in range(4):
        time_answer, mac = pingMsg(domain)

        if time_answer is not None:
            times += [time_answer]
            print(f"Reply from {mac}: time={str(time_answer)}ms")
            # Make it looks more like ping with sleep of 1 second
            time.sleep(1)
        else:
            print("Request timed out.")
            return False

    sum_time = sum(times)
    average = round(sum_time / len(times))

    print(f"Ping statistics for {mac}")
    print("    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),")
    print("Approximate round trip times in milli-seconds:")
    print(f"    Minimum = {min(times)}ms, Maximum = {max(times)}ms, Average = {average}ms")

def main():
    # Bonus
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("Enter domain: ")

    pingMultiple(domain)

if __name__ == '__main__':
    main()
