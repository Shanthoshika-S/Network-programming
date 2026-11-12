# client_1727.py
# IE2102 Network Programming Assignment
# Registration No: IT24101727

import socket
import sys

# ── configuration ──
HOST = '127.0.0.1'
PORT = 50727

def send_framed(sock, message):
    """
    A1 - Custom TCP Protocol
    Sends message using LEN framing:
    LEN:<n>
    <payload>
    """
    payload = message.encode()
    n = len(payload)
    header = f"LEN:{n}\n".encode()
    sock.sendall(header + payload)

def recv_response(sock):
    """
    Receives server response line by line
    Handles partial recv (TCP stream behavior)
    """
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
        if b"\n" in response:
            break
    return response.decode().strip()

def print_banner():
    print("============================================")
    print("  IE2102 NP Assignment Client")
    print("  RegNo : IT24101727")
    print(f"  Server: {HOST}:{PORT}")
    print("============================================")
    print("Commands available:")
    print("  REGISTER <username> <password>")
    print("  LOGIN    <username> <password>")
    print("  LOGOUT")
    print("  STATUS")
    print("  quit  → exit client")
    print("============================================")

def main():
    print_banner()

    # create TCP socket - from Lab 1 and Lab 5
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((HOST, PORT))
        print(f"[*] Connected to server {HOST}:{PORT}\n")
    except ConnectionRefusedError:
        print(f"[!] Could not connect to {HOST}:{PORT}")
        print("[!] Make sure the server is running first.")
        sys.exit(1)

    while True:
        try:
            # get user input
            user_input = input("> ").strip()

            # skip empty input
            if not user_input:
                continue

            # quit command
            if user_input.lower() == 'quit':
                print("[*] Closing connection. Goodbye!")
                break

            # check payload size before sending - A4
            if len(user_input.encode()) > 4096:
                print("[!] Message too long. Max 4096 bytes.")
                continue

            # send framed message - A1
            send_framed(sock, user_input)

            # receive and display response
            response = recv_response(sock)
            print(f"[Server] {response}\n")

        except KeyboardInterrupt:
            print("\n[*] Interrupted. Closing connection.")
            break
        except BrokenPipeError:
            print("[!] Server closed the connection.")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            break

    sock.close()

if __name__ == "__main__":
    main()
