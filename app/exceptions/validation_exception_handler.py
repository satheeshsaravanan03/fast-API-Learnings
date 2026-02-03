from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi import status
from app.constants.error import ERROR


def validation_exception_handler(request, exc: RequestValidationError):

    errors = []

    for err in exc.errors():
        field = err["loc"][-1]

        default_msg = err["msg"]

        custom_msg = getattr(ERROR, f"REQUIRED_{str(field).upper()}", default_msg)

        errors.append({
            "field": field,
            "message": custom_msg
        })

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "statusCode": 400,
            "errors": "Validation failed",
            "message": errors
        }
    )
