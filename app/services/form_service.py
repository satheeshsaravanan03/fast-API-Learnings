from sqlalchemy.orm import Session
from app.schema.user_schema import UserData
from app.models.form_model import Form
from app.models.user_model import User
from app.schema.form_schema import FormCreate
import logging
from app.exceptions import CustomException
from app.constants.error import ERROR
from sqlalchemy import func
from sqlalchemy import and_

logger = logging.getLogger(__name__)

def create_form(db: Session, data: FormCreate, user: UserData):
    try:
        new_form = Form(
            user_id=user.id,
            name=data.name,
            desc=data.description,
            form=data.dict()["filters"],
        )

        db.add(new_form)
        db.commit()
        db.refresh(new_form)

        return new_form

    except Exception as e:
        db.rollback()
        logger.error(f"Error creating form: {e}")
        raise


def get_form_list(db:Session, id:str, page:int, size:int):
    try:
        query = db.query(Form)
        if id is not None:
            form = query.filter(Form.form_id == id).first()
            if not form:
                raise CustomException(status_code=404, message=ERROR.FORM_NOT_FOUND)
            return form
        
        offset = (page -1 ) * size
        total = query.count()
        forms = query.offset(offset).limit(size).all()
        return {
            "page": page,
            "size": size,
            "total": total,
            "users": forms
        }

    except CustomException:
        raise
    except Exception:
        raise CustomException(status_code=500, message=ERROR.INTERNAL_ERROR)

def update_form(db:Session, id:str, data:FormCreate):
    try:
        query = db.query(Form)
        form = query.filter(Form.form_id == id).first()
        if not form:
            raise CustomException(status_code=404, message=ERROR.FORM_NOT_FOUND)

        form.name = data.name
        form.desc = data.description
        form.filters = [f.dict() for f in data.filters]
        db.commit()
        db.refresh(form)  
        return form

    except CustomException:
        raise
    except Exception as e:
        db.rollback()
        print(e)
        raise e

def delete_form(db:Session, id:str):
    try:
        query = db.query(Form)
        form = query.filter(Form.form_id == id).first()
        if not form:
            raise CustomException(status_code=404, message=ERROR.FORM_NOT_FOUND)
        db.delete(form)
        db.commit()
    except CustomException:
        raise
    except Exception as e:
        db.rollback()
        print(e)
        raise e



def get_table_form_list(db: Session, page: int, size: int):
    try:
        offset = (page - 1) * size

        forms = (
            db.query(Form)
            .order_by(Form.created_at.desc())
            .offset(offset)
            .limit(size)
            .all()
        )

        result = []
        total = db.query(Form).count()

        for form in forms:
            filters = build_filters(form.form)

            matched_count = (
                db.query(func.count(User.id))
                .filter(filters)
                .scalar()
            )

            result.append({
                "form_id": form.form_id,
                "name": form.name,
                "desc": form.desc,
                "created_at": form.created_at,
                "matched_user_count": matched_count
            })

        return { "result":result, "total": total, "page": page, "size": size}

    except CustomException:
        raise
    except Exception as e:
        raise CustomException(
            status_code=500,
            message=ERROR.INTERNAL_ERROR
        )



def build_filter_condition(filter_item):
    field_key = filter_item["property"]["value"]
    option = filter_item["filterOption"]["value"]

    if field_key not in ALLOWED_USER_FIELDS:
        raise CustomException(400, f"Invalid filter field: {field_key}")

    column = ALLOWED_USER_FIELDS[field_key]

    text_value = filter_item.get("textValue")
    date_value = filter_item.get("dateValue")
    start_date = filter_item.get("startDate")
    end_date = filter_item.get("endDate")

    if option == "startsWith":
        return column.like(f"{text_value}%")

    if option == "endsWith":
        return column.like(f"%{text_value}")

    if option == "contains":
        return column.like(f"%{text_value}%")

    if option == "beforeDate":
        return column < date_value

    if option == "afterDate":
        return column > date_value

    if option == "betweenDates":
        return column.between(start_date, end_date)

    raise CustomException(400, f"Unsupported filter option: {option}")



def build_filters(form_json):
    conditions = []
    for item in form_json:
        conditions.append(build_filter_condition(item))
    return and_(*conditions)


ALLOWED_USER_FIELDS = {
    "name": User.name,
    "email": User.email,
    "created_at": User.created_at,
    "country": User.country
}
