from fastapi import APIRouter, Depends, UploadFile, File, Request, HTTPException, Header
from sqlalchemy.orm import Session
from app.services import user_service
from app.services.n8n_service import send_verification_email, send_temp_password_email, send_password_changed_email
from app.schema.user_schema import (
    CreateUserRequest, UpdateUserRequest, SignInRequest, ApiResponse, UserResponse,
    VerifyEmailRequest, ResendVerificationRequest, ChangePasswordRequest
)
from app.config.database_config import get_db
from app.config.env_config import settings
from app.middleware.auth_middleware import auth_middleware
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
    """
    Get user by ID or paginated list of users
    SQL: SELECT * FROM users WHERE id = ? OR SELECT * FROM users LIMIT ? OFFSET ?
    """
    response = user_service.get_user_info(db, id, page, size)
    return {
        "statusCode": 200,
        "message": 'Successfully fetched userInfo',
        "data": response
    }


@user_controller.post("/create", response_model=dict)
async def create_new_user(data: CreateUserRequest, request: Request, db: Session = Depends(get_db)):
    """
    Create new user (signup) - no password required
    SQL: INSERT INTO users (id, name, email, ...) VALUES (?, ?, ?, ...)
    Triggers n8n webhook to send verification email
    """
    try:
        # Create user and get verification token
        user, verification_token = user_service.create_user(db, data)

        # Get frontend URL from Origin header or Referer, fallback to env config
        origin = request.headers.get("origin") or request.headers.get("referer", "").rstrip("/")
        frontend_url = origin if origin else settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else "http://localhost:3000"

        # Trigger n8n webhook to send verification email
        email_sent = await send_verification_email(
            user_email=user["email"],
            user_name=user["name"],
            verification_token=verification_token,
            frontend_url=frontend_url
        )

        if not email_sent:
            logger.warning(f"Verification email failed to send for {user['email']}")

        return {
            "statusCode": 200,
            "data": {
                "user": user,
                "message": "User registered successfully. Please check your email to verify your account."
            },
            "message": 'User registered successfully. Verification email sent.'
        }
    except Exception as e:
        handle_route_error(error=e, context="POST /user/create")


@user_controller.post("/verify-email", response_model=dict)
async def verify_email(data: VerifyEmailRequest, db: Session = Depends(get_db)):
    """
    Verify email using JWT token and set temporary password
    SQL: UPDATE users SET is_verified=1, password=?, is_temp_password=1, temp_password_created_at=NOW() WHERE id=?
    Triggers n8n webhook to send temporary password email
    """
    try:
        # Verify email and generate temp password
        result = user_service.verify_email_and_set_temp_password(db, data.token)

        # Trigger n8n webhook to send temp password email
        email_sent = await send_temp_password_email(
            user_email=result["user_email"],
            user_name=result["user_name"],
            temp_password=result["temp_password"]
        )

        if not email_sent:
            logger.warning(f"Temp password email failed to send for {result['user_email']}")

        return {
            "statusCode": 200,
            "message": "Email verified successfully. Temporary password has been sent to your email.",
            "data": {
                "email": result["user_email"],
                "temp_password_sent": True
            }
        }
    except Exception as e:
        handle_route_error(error=e, context="POST /user/verify-email")


@user_controller.post("/resend-verification", response_model=dict)
async def resend_verification(data: ResendVerificationRequest, request: Request, db: Session = Depends(get_db)):
    """
    Resend verification email for unverified users
    SQL: SELECT * FROM users WHERE email=? AND is_verified=0
    Triggers n8n webhook to send new verification email
    """
    try:
        # Get user and generate new verification token
        result = user_service.resend_verification_email(db, data.email)

        # Get frontend URL from Origin header or Referer, fallback to env config
        origin = request.headers.get("origin") or request.headers.get("referer", "").rstrip("/")
        frontend_url = origin if origin else settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else "http://localhost:3000"

        # Trigger n8n webhook to send verification email
        email_sent = await send_verification_email(
            user_email=result["user_email"],
            user_name=result["user_name"],
            verification_token=result["verification_token"],
            frontend_url=frontend_url
        )

        if not email_sent:
            logger.warning(f"Verification email failed to send for {result['user_email']}")

        return {
            "statusCode": 200,
            "message": "Verification email resent successfully. Please check your email.",
            "data": {
                "email": result["user_email"]
            }
        }
    except Exception as e:
        handle_route_error(error=e, context="POST /user/resend-verification")


@user_controller.post("/signin", response_model=dict)
async def signin_user(data: SignInRequest, db: Session = Depends(get_db)):
    """
    User signin with temp password expiry check
    SQL: SELECT id, email, password, is_verified, is_temp_password, temp_password_created_at FROM users WHERE email=?
    Returns JWT tokens and flags if temp password needs to be changed
    """
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
    db: Session = Depends(get_db)
):
    """
    Change password from temporary to permanent
    SQL: UPDATE users SET password=?, is_temp_password=0, temp_password_created_at=NULL WHERE id=?
    Triggers n8n webhook to send password changed confirmation
    """
    try:
        # Change password
        result = user_service.change_password(db, request.state.user, data.new_password)

        # Trigger n8n webhook to send password changed email
        email_sent = await send_password_changed_email(
            user_email=result["user_email"],
            user_name=result["user_name"]
        )

        if not email_sent:
            logger.warning(f"Password changed email failed to send for {result['user_email']}")

        return {
            "statusCode": 200,
            "message": "Password changed successfully.",
            "data": {
                "password_updated": True
            }
        }
    except Exception as e:
        handle_route_error(error=e, context="POST /user/change-password")


@user_controller.put("/update", dependencies=[Depends(auth_middleware)], response_model=ApiResponse[UserResponse])
def update_user(data: UpdateUserRequest, request: Request, db: Session = Depends(get_db)):
    """
    Update user information
    SQL: UPDATE users SET name=?, profile_url=?, ... WHERE id=?
    """
    try:
        response = user_service.update_user_info(db, data, request.state.user)
        return {"statusCode": 200, "data": response, "message": 'User updated successfully.'}
    except Exception as e:
        handle_route_error(error=e, context="PUT /user/update")


@user_controller.delete("", response_model=dict, dependencies=[Depends(auth_middleware)])
def delete_user(request: Request, db: Session = Depends(get_db)):
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
def verify_token(request: Request):
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
