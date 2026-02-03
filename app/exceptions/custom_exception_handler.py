from fastapi.responses import JSONResponse
from app.exceptions.custom_exception import CustomException


def custom_exception_handler(request, exc: CustomException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "statusCode": exc.status_code,
            "message": exc.message
        }
    )
