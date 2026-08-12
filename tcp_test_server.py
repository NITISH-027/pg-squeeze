import socket
import os

HOST = "0.0.0.0"
PORT = 5432

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

server.bind((HOST, PORT))
server.listen(5)

print(f"TCP test server running")
print(f"PID: {os.getpid()}")
print(f"Listening on {HOST}:{PORT}")

while True:
    conn, addr = server.accept()

    print(f"Connection from {addr}")

    try:
        while True:
            data = conn.recv(4096)

            if not data:
                break

            print(f"Received {len(data)} bytes")

            conn.sendall(data)

    except ConnectionResetError:
        pass

    finally:
        conn.close()
        print("Connection closed")
