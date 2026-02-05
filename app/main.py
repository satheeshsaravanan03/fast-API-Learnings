from fastapi import FastAPI
from app.routes.users_router import user_controller
from app.config.database_config import Base, engine
from app.models.user_model import User
from app.exceptions import CustomException, custom_exception_handler, validation_exception_handler
from fastapi.exceptions import RequestValidationError
from app.config.logger_config import setup_logging
from app.utils.logger_utils import log_info
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from app.routes.form_router import form_controller
from app.websocket.chat_socket import chat_websocket

# Initialize logging
setup_logging()

app = FastAPI(
    swagger_ui_parameters={
        "persistAuthorization": True 
    }
)

log_info(context="APP_STARTUP", message="FastAPI application started")


@app.get("/health")
def server_life_check():
    return {"statusCode": 200, "data": "Your server is running successfully"}


Base.metadata.create_all(bind=engine)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(CustomException, custom_exception_handler)

app.include_router(user_controller, prefix="/user", tags=["Users"])
app.include_router(form_controller, prefix="/forms", tags=["Forms"])

origins = [
    # "http://localhost:3000",
    # "http://127.0.0.1:3000",
    # "http://localhost:4321",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allowed frontend URLs
    allow_credentials=True,
    allow_methods=["*"],  # GET, POST, PUT, DELETE...
    allow_headers=["*"],  # Authorization, Content-Type, etc.
)

# Swagger UI will automatically pick up HTTPBearer from route dependencies
# No need for custom OpenAPI configuration


@app.websocket("/chat")
async def chat_endpoint(websocket: WebSocket):
    await chat_websocket(websocket)
