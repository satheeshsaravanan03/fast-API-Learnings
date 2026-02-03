import httpx
from app.config.env_config import settings
import logging

logger = logging.getLogger(__name__)


async def send_verification_email(user_email: str, user_name: str, verification_token: str, frontend_url: str = "http://localhost:3000"):

    try:
        payload = {
            "email": user_email,
            "name": user_name,
            "verification_link": f"{frontend_url}/verify-email?token={verification_token}",
            "token": verification_token
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                settings.N8N_WEBHOOK_VERIFICATION_EMAIL,
                json=payload
            )
            response.raise_for_status()
            logger.info(f"Verification email triggered for {user_email}")
            return True
    except httpx.HTTPError as e:
        logger.error(f"Failed to trigger verification email for {user_email}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error triggering verification email: {str(e)}")
        return False


async def send_temp_password_email(user_email: str, user_name: str, temp_password: str):
    """
    Trigger n8n webhook to send temporary password email

    Args:
        user_email: User's email address
        user_name: User's name
        temp_password: Temporary password (plain text)
    """
    try:
        payload = {
            "email": user_email,
            "name": user_name,
            "temp_password": temp_password,
            "expiry_minutes": settings.TEMP_PASSWORD_EXPIRY_MINUTES
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                settings.N8N_WEBHOOK_TEMP_PASSWORD_EMAIL,
                json=payload
            )
            response.raise_for_status()
            logger.info(f"Temporary password email triggered for {user_email}")
            return True
    except httpx.HTTPError as e:
        logger.error(f"Failed to trigger temp password email for {user_email}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error triggering temp password email: {str(e)}")
        return False


async def send_password_changed_email(user_email: str, user_name: str):
    """
    Trigger n8n webhook to send password changed confirmation email

    Args:
        user_email: User's email address
        user_name: User's name
    """
    try:
        payload = {
            "email": user_email,
            "name": user_name
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                settings.N8N_WEBHOOK_PASSWORD_CHANGED_EMAIL,
                json=payload
            )
            response.raise_for_status()
            logger.info(f"Password changed email triggered for {user_email}")
            return True
    except httpx.HTTPError as e:
        logger.error(f"Failed to trigger password changed email for {user_email}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error triggering password changed email: {str(e)}")
        return False
