from pydantic import BaseModel
from typing import List, Optional


class SelectOption(BaseModel):
    value: str
    label: str


class FilterItem(BaseModel):
    property: SelectOption
    filterOption: SelectOption
    textValue: Optional[str] = ""
    dateValue: Optional[str] = ""
    startDate: Optional[str] = ""
    endDate: Optional[str] = ""


class FormCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    filters: List[FilterItem]
