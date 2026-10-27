
import os
import psycopg2
from fastapi import HTTPException


def get_db_connection():
    db_password = os.environ.get("DB_PASSWORD")

    if not db_password:
        raise HTTPException(
            status_code=500,
            detail="DB_PASSWORD is not configured"
        )

    return psycopg2.connect(
        host="localhost",
        database="secure_customer_chatbot",
        user="postgres",
        password=db_password,
        port=5432
    )
