import httpx
from app.config.env_config import settings
import logging

logger = logging.getLogger(__name__)


async def send_otp_email(user_email: str, user_name: str, otp: str):
    """
    Trigger n8n webhook to send OTP verification email

    Args:
        user_email: User's email address
        user_name: User's name
        otp: 6-digit OTP code
    """
    try:
        payload = {
            "email": user_email,
            "name": user_name,
            "otp": otp,
            "expiry_minutes": settings.OTP_EXPIRY_MINUTES
        }

        webhook_url = f"{settings.N8N_WEBHOOK_BASE_URL}/send-otp"

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(webhook_url, json=payload)
            response.raise_for_status()
            logger.info(f"OTP email triggered for {user_email}")
            return True
    except httpx.HTTPError as e:
        logger.error(f"Failed to trigger OTP email for {user_email}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error triggering OTP email: {str(e)}")
        return False
