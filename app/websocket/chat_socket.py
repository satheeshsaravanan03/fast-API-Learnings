from fastapi import WebSocket, WebSocketDisconnect
from app.websocket.manager_socket import ConnectionManager
from app.utils.auth_utils import generate_jwt, verify_jwt
from app.config.env_config import settings


manager = ConnectionManager()


async def chat_websocket(websocket: WebSocket):
    token = websocket.query_params.get("token")

    if not token:
        await websocket.close(code=4001)
        return

    try:
        if token.startswith("Bearer "):
            token = token[7:] 
            
        payload = verify_jwt(token=token, secret_key=settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        user_id = payload["id"]
    except:
        await websocket.close(code=4001)
        return

    await manager.connect(user_id=user_id, websocket=websocket)
    print(f" {user_id} connected.....")

    try:
        while True:
            data = await websocket.receive_json()
            await manager.send_personal_message(
                data["to"],
                {
                    "from": user_id,
                    "message": data["message"]
                }
            )
    except WebSocketDisconnect:
        manager.disconnect(user_id)
        print(f" {user_id} disconnected...")
