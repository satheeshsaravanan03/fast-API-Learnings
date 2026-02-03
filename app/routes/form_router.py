
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session, Query
from app.config.database_config import get_db
from app.models.form_model import Form
from app.middleware.auth_middleware import auth_middleware
from app.utils.logger_utils import handle_route_error
from app.services.form_service import create_form, get_form_list, update_form, delete_form, get_table_form_list
from app.schema.form_schema import FormCreate

form_controller = APIRouter()

@form_controller.post("/create", response_model=dict, dependencies=[Depends(auth_middleware)])
def handle_create_form(request: Request, data: FormCreate, db: Session = Depends(get_db)):
    try:
        create_form(db, data, request.state.user)
        return {"statusCode": 201, "message": "Successfully Created"}
    except Exception as e:
        handle_route_error(error=e, context="POST /forms/create")


@form_controller.get("", response_model=dict, dependencies=[Depends(auth_middleware)])
def handle_create_form(
    id: str | None = None,
    page: int = 1,
    limit: int = 10,
    db: Session = Depends(get_db),
):
    try:
        response = get_form_list(db, id, page, limit)
        return {"statusCode": 201, "message": "Successfully Created", "data" : response}
    except Exception as e:
        handle_route_error(error=e, context="POST /forms/create")

@form_controller.put("/update", response_model=dict, dependencies=[Depends(auth_middleware)])
def handle_update_form(
    id: str,
    data: FormCreate,
    db: Session = Depends(get_db),
):
    try:
        response = update_form(db, id, data)
        return {"statusCode": 201, "message": "Successfully Updated", "data" : response}
    except Exception as e:
        handle_route_error(error=e, context="POST /forms/update")

@form_controller.delete("", response_model=dict, dependencies=[Depends(auth_middleware)])
def handle_delete_form(
    id: str,
    db: Session = Depends(get_db),
):
    try:
        delete_form(db, id,)
        return {"statusCode": 201, "message": "Successfully Deleted", "data" : []}
    except Exception as e:
        handle_route_error(error=e, context="POST /forms/delete")


@form_controller.get("/list", response_model=dict, dependencies=[Depends(auth_middleware)])
def table_form_list(db:Session = Depends(get_db), page : int = 1, size : int = 10):
    try:
      response = get_table_form_list(db, page, size)
      return {"statusCode": 201, "message": "Successfully Updated", "data" : response}
    except Exception as e:
        handle_route_error(error=e, context="GET /forms/table-list")
    