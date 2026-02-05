from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import text
from app.schema.user_schema import CreateUserRequest, UpdateUserRequest, SignInRequest, UserData
from app.exceptions import CustomException
from app.constants.error import ERROR
import uuid
from app.utils.auth_utils import verify_password, hash_password, generate_jwt, verify_jwt
from app.config.env_config import settings
from datetime import datetime
import logging
import random
import re

logger = logging.getLogger(__name__)


def validate_password_strength(password: str) -> tuple[bool, str]:

    if len(password) < 6:
        return False, "Password must be at least 6 characters long"

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"

    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;/~`]', password):
        return False, "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>_-+=[]\\;/~`)"

    return True, ""


def generate_otp() -> str:
    """Generate a 6-digit OTP code"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])


def get_user_info(db: Session, id: str, page: int, size: int):
    """
    Get user by ID or paginated list of all users using raw SQL
    """
    try:
        if id is not None:
            # Raw SQL query to fetch user by ID
            query = text("""
                SELECT id, name, email, password, country, profile_url, about, user_role,
                       is_verified, is_temp_password, temp_password_created_at,
                       created_at, updated_at
                FROM users
                WHERE id = :user_id
            """)
            result = db.execute(query, {"user_id": id})
            user = result.fetchone()

            if not user:
                raise CustomException(status_code=404, message=ERROR.USER_NOT_FOUND)

            # Convert row to dict
            return {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "country": user.country,
                "profile_url": user.profile_url,
                "about": user.about,
                "user_role": user.user_role,
                "is_verified": user.is_verified,
                "is_temp_password": user.is_temp_password,
                "created_at": user.created_at,
                "updated_at": user.updated_at
            }

        # Pagination for all users
        offset = (page - 1) * size

        # Count total users
        count_query = text("SELECT COUNT(*) as total FROM users")
        total_result = db.execute(count_query)
        total = total_result.fetchone().total

        # Fetch paginated users
        users_query = text("""
            SELECT id, name, email, country, profile_url, about, user_role,
                   is_verified, is_temp_password, created_at, updated_at
            FROM users
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """)
        users_result = db.execute(users_query, {"limit": size, "offset": offset})
        users = users_result.fetchall()

        # Convert rows to list of dicts
        users_list = [
            {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "country": user.country,
                "profile_url": user.profile_url,
                "about": user.about,
                "user_role": user.user_role,
                "is_verified": user.is_verified,
                "is_temp_password": user.is_temp_password,
                "created_at": user.created_at,
                "updated_at": user.updated_at
            }
            for user in users
        ]

        return {
            "page": page,
            "size": size,
            "total": total,
            "users": users_list
        }

    except CustomException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error in get_user_info: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)
    except Exception as e:
        logger.error(f"Error in get_user_info: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)


def create_user(db: Session, data: CreateUserRequest):
    """
    Create new user without password (will be set after OTP verification)
    Returns user object and 6-digit OTP code using raw SQL INSERT
    """
    try:
        user_id = str(uuid.uuid4())
        current_time = datetime.utcnow()
        otp = generate_otp()

        # Raw SQL INSERT query
        insert_query = text("""
            INSERT INTO users (id, name, email, password, country, profile_url, about,
                             user_role, is_verified, is_temp_password, otp, otp_created_at,
                             created_at, updated_at)
            VALUES (:id, :name, :email, :password, :country, :profile_url, :about,
                    :user_role, :is_verified, :is_temp_password, :otp, :otp_created_at,
                    :created_at, :updated_at)
        """)

        db.execute(insert_query, {
            "id": user_id,
            "name": data.name,
            "email": data.email,
            "password": None,  # Will be set after OTP verification
            "country": "India",
            "profile_url": data.profile_url,
            "about": data.about,
            "user_role": 1,  # Default user role
            "is_verified": False,
            "is_temp_password": False,
            "otp": otp,
            "otp_created_at": current_time,
            "created_at": current_time,
            "updated_at": current_time
        })
        db.commit()

        # Fetch created user
        select_query = text("""
            SELECT id, name, email, country, profile_url, about, user_role,
                   is_verified, created_at, updated_at
            FROM users
            WHERE id = :user_id
        """)
        result = db.execute(select_query, {"user_id": user_id})
        new_user = result.fetchone()

        return {
            "id": new_user.id,
            "name": new_user.name,
            "email": new_user.email,
            "country": new_user.country,
            "profile_url": new_user.profile_url,
            "about": new_user.about,
            "is_verified": new_user.is_verified,
            "created_at": new_user.created_at
        }, otp

    except IntegrityError as e:
        db.rollback()
        logger.error(f"Integrity error - email already exists: {e}")
        raise CustomException(status_code=409, message=ERROR.EMAIL_ALREADY_EXISTS)
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error in create_user: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating user: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)


def update_user_info(db: Session, data: UpdateUserRequest, user: UserData):
    """
    Update user information using raw SQL UPDATE query
    """
    try:
        # Check if user exists
        check_query = text("SELECT id FROM users WHERE id = :user_id")
        result = db.execute(check_query, {"user_id": user.id})
        if not result.fetchone():
            raise CustomException(status_code=404, message=ERROR.USER_NOT_FOUND)

        # Build dynamic UPDATE query based on provided fields
        update_fields = data.dict(exclude_unset=True)
        if not update_fields:
            raise CustomException(status_code=400, message="No fields to update")

        # Remove id if present
        update_fields.pop("id", None)

        # Hash password if updating
        if "password" in update_fields:
            update_fields["password"] = hash_password(update_fields["password"])

        # Add updated_at
        update_fields["updated_at"] = datetime.utcnow()

        # Build SQL dynamically
        set_clause = ", ".join([f"{key} = :{key}" for key in update_fields.keys()])
        update_query = text(f"""
            UPDATE users
            SET {set_clause}
            WHERE id = :user_id
        """)

        # Add user_id to params
        params = {**update_fields, "user_id": user.id}
        db.execute(update_query, params)
        db.commit()

        # Fetch updated user
        select_query = text("""
            SELECT id, name, email, country, profile_url, about, user_role,
                   is_verified, created_at, updated_at
            FROM users
            WHERE id = :user_id
        """)
        result = db.execute(select_query, {"user_id": user.id})
        updated_user = result.fetchone()

        return {
            "id": updated_user.id,
            "name": updated_user.name,
            "email": updated_user.email,
            "country": updated_user.country,
            "profile_url": updated_user.profile_url,
            "about": updated_user.about,
            "user_role": updated_user.user_role,
            "is_verified": updated_user.is_verified,
            "created_at": updated_user.created_at,
            "updated_at": updated_user.updated_at
        }

    except CustomException:
        raise
    except IntegrityError:
        db.rollback()
        raise CustomException(status_code=409, message=ERROR.EMAIL_ALREADY_EXISTS)
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error in update_user_info: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating user: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)


def delete_user_info(db: Session, user: UserData):
    """
    Delete user using raw SQL DELETE query
    """
    try:
        # Check if user exists
        check_query = text("SELECT id FROM users WHERE id = :user_id")
        result = db.execute(check_query, {"user_id": user.id})
        if not result.fetchone():
            raise CustomException(status_code=404, message=ERROR.USER_NOT_FOUND)

        # Delete user
        delete_query = text("DELETE FROM users WHERE id = :user_id")
        db.execute(delete_query, {"user_id": user.id})
        db.commit()

        logger.info(f"User {user.id} deleted successfully")

    except CustomException:
        raise
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error in delete_user_info: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting user: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)


def sign_in_user(db: Session, data: SignInRequest):
    """
    User signin using raw SQL SELECT
    """
    try:
        # Fetch user by email
        query = text("""
            SELECT id, name, email, password, profile_url, user_role, is_verified
            FROM users
            WHERE email = :email
        """)
        result = db.execute(query, {"email": data.email})
        user_info = result.fetchone()

        if not user_info:
            raise CustomException(status_code=404, message=ERROR.INVALID_CREDENTIALS)

        # Check if user is verified
        if not user_info.is_verified:
            raise CustomException(status_code=403, message="Email not verified. Please verify your email first.")

        # Check if password is set
        if not user_info.password:
            raise CustomException(status_code=403, message="Password not set. Please complete OTP verification.")

        # Verify password
        is_valid = verify_password(password=data.password, hashed=user_info.password)
        if not is_valid:
            raise CustomException(status_code=401, message=ERROR.INVALID_CREDENTIALS)

        # Generate JWT tokens
        user_data = {
            "id": user_info.id,
            "email": user_info.email,
            "name": user_info.name,
            "profile_url": user_info.profile_url,
            "user_role": user_info.user_role
        }

        auth_token = generate_jwt(
            data=user_data,
            expire_minutes=settings.ACCESS_TOKEN_EXP_TIME,
            secret_key=settings.SECRET_KEY,
            algorithm=settings.ALGORITHM
        )
        refresh_token = generate_jwt(
            data=user_data,
            expire_minutes=settings.REFRESH_TOKEN_EXP_TIME,
            secret_key=settings.REFRESH_SECRET_KEY,
            algorithm=settings.ALGORITHM
        )

        return {
            "authToken": auth_token,
            "refreshToken": refresh_token,
            "user": user_data
        }

    except CustomException:
        raise
    except Exception as e:
        logger.error(f"Error signing in user: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)


def verify_otp_and_set_password(db: Session, email: str, otp: str, new_password: str):
    """
    Verify OTP and set user password using raw SQL UPDATE
    """
    try:
        # Validate password strength first
        is_valid, error_message = validate_password_strength(new_password)
        if not is_valid:
            raise CustomException(status_code=400, message=error_message)

        # Check if user exists with matching OTP
        check_query = text("""
            SELECT id, name, email, is_verified, otp, otp_created_at
            FROM users
            WHERE email = :email
        """)
        result = db.execute(check_query, {"email": email})
        user = result.fetchone()

        if not user:
            raise CustomException(status_code=404, message=ERROR.USER_NOT_FOUND)

        if user.is_verified:
            raise CustomException(status_code=400, message="Email already verified. Please login.")

        if not user.otp or not user.otp_created_at:
            raise CustomException(status_code=400, message="No OTP found. Please request a new verification email.")

        # Check if OTP matches
        if user.otp != otp:
            raise CustomException(status_code=400, message="Invalid OTP code")

        # Check if OTP expired (10 minutes)
        time_elapsed = datetime.utcnow() - user.otp_created_at
        elapsed_minutes = time_elapsed.total_seconds() / 60

        if elapsed_minutes > settings.OTP_EXPIRY_MINUTES:
            raise CustomException(
                status_code=400,
                message="OTP expired. Please request a new verification email."
            )

        # Hash the new password
        hashed_password = hash_password(new_password)

        # Update user: set password, mark as verified, clear OTP
        update_query = text("""
            UPDATE users
            SET password = :password,
                is_verified = :is_verified,
                otp = NULL,
                otp_created_at = NULL,
                updated_at = :updated_at
            WHERE id = :user_id
        """)

        db.execute(update_query, {
            "password": hashed_password,
            "is_verified": True,
            "updated_at": datetime.utcnow(),
            "user_id": user.id
        })
        db.commit()

        logger.info(f"OTP verified and password set for user {user.id}")

        # Generate JWT tokens for immediate login
        user_data = {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "profile_url": None,
            "user_role": 1
        }

        auth_token = generate_jwt(
            data=user_data,
            expire_minutes=settings.ACCESS_TOKEN_EXP_TIME,
            secret_key=settings.SECRET_KEY,
            algorithm=settings.ALGORITHM
        )
        refresh_token = generate_jwt(
            data=user_data,
            expire_minutes=settings.REFRESH_TOKEN_EXP_TIME,
            secret_key=settings.REFRESH_SECRET_KEY,
            algorithm=settings.ALGORITHM
        )

        return {
            "user_id": user.id,
            "user_name": user.name,
            "user_email": user.email,
            "authToken": auth_token,
            "refreshToken": refresh_token,
            "user": user_data
        }

    except CustomException:
        raise
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error in verify_otp_and_set_password: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)
    except Exception as e:
        db.rollback()
        logger.error(f"Error verifying OTP: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)


def resend_verification_email(db: Session, email: str):
    """
    Resend OTP for unverified user using raw SQL
    """
    try:
        # Check if user exists
        query = text("""
            SELECT id, name, email, is_verified
            FROM users
            WHERE email = :email
        """)
        result = db.execute(query, {"email": email})
        user = result.fetchone()

        if not user:
            raise CustomException(status_code=404, message=ERROR.USER_NOT_FOUND)

        if user.is_verified:
            raise CustomException(status_code=400, message="Email already verified. Please login.")

        # Generate new OTP
        otp = generate_otp()
        current_time = datetime.utcnow()

        # Update OTP in database
        update_query = text("""
            UPDATE users
            SET otp = :otp,
                otp_created_at = :otp_created_at,
                updated_at = :updated_at
            WHERE id = :user_id
        """)

        db.execute(update_query, {
            "otp": otp,
            "otp_created_at": current_time,
            "updated_at": current_time,
            "user_id": user.id
        })
        db.commit()

        return {
            "user_id": user.id,
            "user_name": user.name,
            "user_email": user.email,
            "otp": otp
        }

    except CustomException:
        raise
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error in resend_verification_email: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)
    except Exception as e:
        db.rollback()
        logger.error(f"Error in resend_verification_email: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)


def change_password(db: Session, user: UserData, current_password: str, new_password: str):
    """
    Change user password (requires current password verification) using raw SQL UPDATE
    """
    try:
        # Fetch user's current password
        check_query = text("SELECT password FROM users WHERE id = :user_id")
        result = db.execute(check_query, {"user_id": user.id})
        user_info = result.fetchone()

        if not user_info or not user_info.password:
            raise CustomException(status_code=404, message=ERROR.USER_NOT_FOUND)

        # Verify current password
        is_valid = verify_password(password=current_password, hashed=user_info.password)
        if not is_valid:
            raise CustomException(status_code=401, message="Current password is incorrect")

        # Validate new password strength
        is_valid, error_message = validate_password_strength(new_password)
        if not is_valid:
            raise CustomException(status_code=400, message=error_message)

        # Hash new password
        hashed_password = hash_password(new_password)

        # Update password
        update_query = text("""
            UPDATE users
            SET password = :password,
                updated_at = :updated_at
            WHERE id = :user_id
        """)

        db.execute(update_query, {
            "password": hashed_password,
            "updated_at": datetime.utcnow(),
            "user_id": user.id
        })
        db.commit()

        logger.info(f"Password changed successfully for user {user.id}")

        return {
            "password_updated": True
        }

    except CustomException:
        raise
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error in change_password: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)
    except Exception as e:
        db.rollback()
        logger.error(f"Error changing password: {e}", exc_info=True)
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)


def refresh_token(token: str):
    """
    Refresh JWT tokens
    """
    try:
        user_data = verify_jwt(token=token, secret_key=settings.REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM)
        if not user_data:
            raise CustomException(status_code=404, message=ERROR.UNAUTHORIZED)

        auth_token = generate_jwt(
            data=user_data,
            expire_minutes=settings.ACCESS_TOKEN_EXP_TIME,
            secret_key=settings.SECRET_KEY,
            algorithm=settings.ALGORITHM
        )
        refresh_token = generate_jwt(
            data=user_data,
            expire_minutes=settings.REFRESH_TOKEN_EXP_TIME,
            secret_key=settings.REFRESH_SECRET_KEY,
            algorithm=settings.ALGORITHM
        )

        return {"authToken": auth_token, "refreshToken": refresh_token}

    except CustomException:
        raise
    except Exception:
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)
