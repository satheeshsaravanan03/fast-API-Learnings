import logging
from typing import Optional
from app.exceptions.custom_exception import CustomException

# Single logger instance for the entire application
logger = logging.getLogger("app")


def log_info(context: str, message: str) -> None:
    """Log informational message with context"""
    logger.info(f"[{context}] {message}")


def log_warning(context: str, message: str) -> None:
    """Log warning message with context"""
    logger.warning(f"[{context}] {message}")


def log_debug(context: str, message: str) -> None:
    """Log debug message with context"""
    logger.debug(f"[{context}] {message}")


def handle_service_error(
    error: Exception,
    context: str,
    custom_exception: Optional[CustomException] = None
) -> None:
    """
    Handle service layer errors with logging

    Args:
        error: The exception that occurred
        context: Context information (e.g., 'create_user', 'update_user')
        custom_exception: Optional CustomException to raise, if None raises the original error

    Raises:
        CustomException or the original exception
    """
    error_msg = str(error) if str(error) else error.__class__.__name__
    logger.error(f"[SERVICE ERROR] {context}: {error_msg}", exc_info=True)

    if custom_exception:
        raise custom_exception
    raise error


def handle_route_error(
    error: Exception,
    context: str
) -> None:

    error_msg = str(error) if str(error) else error.__class__.__name__
    logger.error(f"[ROUTE ERROR] {context}: {error_msg}", exc_info=True)
    raise error


def handle_middleware_error(
    error: Exception,
    context: str,
    custom_exception: Optional[CustomException] = None
) -> None:
   
    error_msg = str(error) if str(error) else error.__class__.__name__
    logger.error(f"[MIDDLEWARE ERROR] {context}: {error_msg}", exc_info=True)

    if custom_exception:
        raise custom_exception
    raise error


def log_database_operation(
    operation: str,
    context: str,
    details: Optional[dict] = None
) -> None:

    message = f"[DB {operation}] {context}"
    if details:
        message += f" - {details}"
    logger.debug(message)
