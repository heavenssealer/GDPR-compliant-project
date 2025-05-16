import re
from typing import Optional, Annotated
from pydantic import BaseModel, EmailStr, Field, field_validator


class ConnectionDetails(BaseModel):
    email: EmailStr
    password: Annotated[
        str,
        Field(
            min_length=13,
            max_length=50,
            description="13–50 chars, must include upper, lower, digit & special (no <>)."
        )
    ]
    connection_attempts: Optional[int] = None
    last_connection_attempt: Optional[int] = None
    role: Optional[str] = None

    @field_validator("password")
    @classmethod
    def check_password(cls, v: str) -> str:
        errors = []
        if not re.search(r"[a-z]", v):
            errors.append("lowercase")
        if not re.search(r"[A-Z]", v):
            errors.append("uppercase")
        if not re.search(r"\d", v):
            errors.append("digit")
        # special chars excluding `<` and `>`
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};:'\"\\|,./?]", v):
            errors.append("special")
        if re.search(r"[<>]", v):
            errors.append("forbidden `<` or `>`")

        if errors:
            detail = ", ".join(errors)
            raise ValueError(f"password must include: {detail}")
        return v
