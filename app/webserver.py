# server.py
import asyncio
import websockets
import base64
from cryptography.fernet import Fernet

# --- Encryption Setup ---
key_file = "encryption_key.key"
try:
    with open(key_file, "rb") as f:
        key = f.read()
except FileNotFoundError:
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)

cipher = Fernet(key)

# --- Clients List ---
connected_clients = set()

async def echo(websocket, path):
    print("🔵 New client connected!")
    connected_clients.add(websocket)
    try:
        async for message in websocket:
            decrypted = cipher.decrypt(base64.b64decode(message)).decode()
            print(f"📩 Received (decrypted): {decrypted}")

            # Echo back (re-encrypted)
            response = f"Echo: {decrypted}"
            encrypted_response = cipher.encrypt(response.encode())
            encoded_response = base64.b64encode(encrypted_response).decode()

            await websocket.send(encoded_response)
    except websockets.ConnectionClosed:
        print("🔴 Client disconnected")
    finally:
        connected_clients.remove(websocket)

async def main():
    async with websockets.serve(echo, "localhost", 8765):
        print("🚀 WebSocket server started at ws://localhost:8765")
        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main())
