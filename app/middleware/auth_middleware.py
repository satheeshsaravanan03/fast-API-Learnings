from fastapi import Request, HTTPException
from app.utils.auth_utils import verify_jwt
from app.config.env_config import settings
from app.exceptions.custom_exception import CustomException
from app.constants.error import ERROR
from app.schema.user_schema import UserData
from app.utils.logger_utils import handle_middleware_error

def auth_middleware(request: Request):
    try:
        token = request.headers.get("Authorization")
        if token is None:
            raise HTTPException(status_code=401, detail="Authorization header missing")
        
        if token.startswith("Bearer "):
            token = token[7:]   

        user = verify_jwt(
            token=token,
            secret_key=settings.SECRET_KEY,
            algorithm=settings.ALGORITHM
        )

        if not user:
            raise ERROR.UNAUTHORIZED


        request.state.user = UserData(**user)

    except Exception as e:
        handle_middleware_error(
            error=e,
            context="auth_middleware",
            custom_exception=CustomException(status_code=401, message=ERROR.UNAUTHORIZED)
        )






    