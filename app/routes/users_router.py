from fastapi import APIRouter, Depends, UploadFile, File, Request, HTTPException, Header
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.services import user_service
from app.services.n8n_service import send_otp_email
from app.schema.user_schema import (
    CreateUserRequest, UpdateUserRequest, SignInRequest, ApiResponse, UserResponse,
    VerifyOTPRequest, ResendVerificationRequest, ChangePasswordRequest
)
from app.config.database_config import get_db
from app.config.env_config import settings
from app.middleware.auth_middleware import auth_middleware, security
from app.utils.logger_utils import handle_route_error
import logging

logger = logging.getLogger(__name__)

user_controller = APIRouter()


@user_controller.get("", response_model=dict)
def get_users(
    id: str | None = None,
    page: int = 1,
    size: int = 10,
    db: Session = Depends(get_db)
):

    response = user_service.get_user_info(db, id, page, size)
    return {
        "statusCode": 200,
        "message": 'Successfully fetched userInfo',
        "data": response
    }


@user_controller.post("/create", response_model=dict, status_code=201)
async def create_new_user(data: CreateUserRequest, request: Request, db: Session = Depends(get_db)):

    try:
        # Create user and get OTP
        user, otp = user_service.create_user(db, data)

        # Trigger n8n webhook to send OTP email
        email_sent = await send_otp_email(
            user_email=user["email"],
            user_name=user["name"],
            otp=otp
        )

        if not email_sent:
            logger.warning(f"OTP email failed to send for {user['email']}")

        return {
            "statusCode": 201,
            "data": {
                "user": user,
                "message": "User registered successfully. Please check your email for OTP verification."
            },
            "message": 'User registered successfully. OTP sent to email.'
        }
    except Exception as e:
        handle_route_error(error=e, context="POST /user/create")


@user_controller.post("/verify-otp", response_model=dict)
async def verify_otp(data: VerifyOTPRequest, db: Session = Depends(get_db)):

    try:
        # Verify OTP and set password
        result = user_service.verify_otp_and_set_password(db, data.email, data.otp, data.new_password)

        return {
            "statusCode": 200,
            "message": "Email verified successfully. You are now logged in.",
            "data": {
                "authToken": result["authToken"],
                "refreshToken": result["refreshToken"],
                "user": result["user"]
            }
        }
    except Exception as e:
        handle_route_error(error=e, context="POST /user/verify-otp")


@user_controller.post("/resend-verification", response_model=dict)
async def resend_verification(data: ResendVerificationRequest, db: Session = Depends(get_db)):

    try:
        # Get user and generate new OTP
        result = user_service.resend_verification_email(db, data.email)

        # Trigger n8n webhook to send OTP email
        email_sent = await send_otp_email(
            user_email=result["user_email"],
            user_name=result["user_name"],
            otp=result["otp"]
        )

        if not email_sent:
            logger.warning(f"OTP email failed to send for {result['user_email']}")

        return {
            "statusCode": 200,
            "message": "OTP resent successfully. Please check your email.",
            "data": {
                "email": result["user_email"]
            }
        }
    except Exception as e:
        handle_route_error(error=e, context="POST /user/resend-verification")


@user_controller.post("/signin", response_model=dict)
async def signin_user(data: SignInRequest, db: Session = Depends(get_db)):
   
    try:
        response = user_service.sign_in_user(db, data)
        return {
            "statusCode": 200,
            "data": response,
            "message": 'User signed in successfully.'
        }
    except Exception as e:
        handle_route_error(error=e, context="POST /user/signin")


@user_controller.post("/change-password", response_model=dict, dependencies=[Depends(auth_middleware)])
async def change_user_password(
    data: ChangePasswordRequest,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):

    try:
        # Change password with current password verification
        result = user_service.change_password(db, request.state.user, data.current_password, data.new_password)

        return {
            "statusCode": 200,
            "message": "Password changed successfully.",
            "data": result
        }
    except Exception as e:
        handle_route_error(error=e, context="POST /user/change-password")


@user_controller.put("/update", dependencies=[Depends(auth_middleware)], response_model=ApiResponse[UserResponse])
def update_user(data: UpdateUserRequest, request: Request, credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
 
    try:
        response = user_service.update_user_info(db, data, request.state.user)
        return {"statusCode": 200, "data": response, "message": 'User updated successfully.'}
    except Exception as e:
        handle_route_error(error=e, context="PUT /user/update")


@user_controller.delete("", response_model=dict, dependencies=[Depends(auth_middleware)])
def delete_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    """
    Delete user account
    SQL: DELETE FROM users WHERE id=?
    """
    try:
        response = user_service.delete_user_info(db, request.state.user)
        return {"statusCode": 200, "message": 'User deleted successfully.', "data": response}
    except Exception as e:
        handle_route_error(error=e, context="DELETE /user")


@user_controller.get("/verify-token", response_model=dict, dependencies=[Depends(auth_middleware)])
def verify_token(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Verify JWT access token validity
    """
    return {
        "statusCode": 200,
        "message": "Token is valid",
        "data": {
            "isValid": True,
            "user": request.state.user
        }
    }


@user_controller.get("/refreshToken", response_model=dict)
async def refresh_user_token(authorization: str = Header(...)):
    """
    Refresh JWT tokens using refresh token
    """
    try:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid token format")
        response = user_service.refresh_token(token=authorization[7:])
        return {"statusCode": 200, "data": response, "message": 'User token refreshed successfully.'}
    except Exception as e:
        handle_route_error(error=e, context="GET /user/refreshToken")


@user_controller.post("/upload", response_model=dict)
async def upload_file(file: list[UploadFile] = File(...)):
    """
    Upload file endpoint (existing functionality)
    """
    content = await file[0].read()

    with open(file[0].filename, "wb") as f:
        f.write(content)

    return {
        "statusCode": 201,
        "data": {
            "filename": file[0].filename,
            "content_type": file[0].content_type,
            "message": "File uploaded successfully"
        }
    }
