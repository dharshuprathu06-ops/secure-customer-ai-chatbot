import os
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import psycopg2
import requests
import jwt


from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from rag import search_customer_invoices


app = FastAPI(title="Secure Customer AI Chatbot")


# 1. Configuration


JWT_SECRET = os.getenv("JWT_SECRET")
OTP_SECRET = os.getenv("OTP_SECRET")
JWT_ALGORITHM = "HS256"

OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "llama3.2:1b"

security = HTTPBearer()


# 2. Request models

class OTPRequest(BaseModel):
    phone: str


class OTPVerifyRequest(BaseModel):
    phone: str
    otp: str


class ChatMessageRequest(BaseModel):
    conversation_id: int | None = None
    message: str


# 3. Database connection

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



# 4. Authentication helper

def get_current_customer(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    if not JWT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="JWT_SECRET is not configured"
        )

    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM]
        )

        customer_id = int(payload["sub"])
        return customer_id

    except (
        jwt.InvalidTokenError,
        KeyError,
        ValueError,
        TypeError
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )



# 5. Home endpoint

@app.get("/")
def home():
    return {
        "message": "Secure Customer AI Chatbot is running"
    }

@app.get("/debug-config")
def debug_config():
    return {
        "db_password_set": bool(os.getenv("DB_PASSWORD")),
        "otp_secret_set": bool(os.getenv("OTP_SECRET")),
        "jwt_secret_set": bool(os.getenv("JWT_SECRET"))
    }


# 6. Database test endpoint

@app.get("/db-test")
def test_db():
    conn = get_db_connection()
    cur = None

    try:
        cur = conn.cursor()

        cur.execute("""
            SELECT current_database(),
                   current_schema(),
                   current_user
        """)
        db_info = cur.fetchone()

        cur.execute("""
            SELECT table_schema, table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            ORDER BY table_name
        """)
        tables = cur.fetchall()

        return {
            "database": db_info[0],
            "schema": db_info[1],
            "user": db_info[2],
            "tables": [
                {"schema": row[0], "table": row[1]}
                for row in tables
            ]
        }

    except psycopg2.Error as e:
        print("Database test error:", e)
        raise HTTPException(
            status_code=500,
            detail="Database test failed"
        )

    finally:
        if cur is not None:
            cur.close()
        conn.close()

# 7. Get logged-in customer's details


@app.get("/customers")
def get_customers(
    customer_id: int = Depends(get_current_customer)
):
    conn = get_db_connection()
    cur = None

    try:
        cur = conn.cursor()

        cur.execute("""
            SELECT id, name, phone
            FROM public.customers
            WHERE id = %s
        """, (customer_id,))

        row = cur.fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail="Customer not found"
            )

        return {
            "id": row[0],
            "name": row[1],
            "phone": row[2]
        }

    except HTTPException:
        raise

    except psycopg2.Error as e:
        print("Customer database error:", e)
        raise HTTPException(
            status_code=500,
            detail="Could not retrieve customer data"
        )

    finally:
        if cur is not None:
            cur.close()
        conn.close()



# 8. Get customer's invoices

@app.get("/customers/{customer_id}/invoices")
def get_customer_invoices(
    customer_id: int,
    current_customer_id: int = Depends(get_current_customer)
):
    if customer_id != current_customer_id:
        raise HTTPException(
            status_code=403,
            detail="You can only access your own invoices"
        )

    conn = get_db_connection()
    cur = None

    try:
        cur = conn.cursor()

        cur.execute("""
            SELECT invoice_number, invoice_date, amount,
                   currency, payment_status
            FROM public.invoices
            WHERE customer_id = %s
            ORDER BY invoice_date, invoice_number
        """, (customer_id,))

        rows = cur.fetchall()

        return [
            {
                "invoice_number": row[0],
                "invoice_date": row[1].isoformat(),
                "amount": float(row[2]),
                "currency": row[3],
                "payment_status": row[4]
            }
            for row in rows
        ]

    except HTTPException:
        raise

    except psycopg2.Error as e:
        print("Invoice database error:", e)
        raise HTTPException(
            status_code=500,
            detail="Could not retrieve invoice data"
        )

    finally:
        if cur is not None:
            cur.close()
        conn.close()



# 9. Request OTP

@app.post("/request-otp")
def request_otp(request: OTPRequest):
    phone = request.phone.strip()

    if not OTP_SECRET:
        raise HTTPException(
            status_code=500,
            detail="OTP_SECRET is not configured"
        )

    if not JWT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="JWT_SECRET is not configured"
        )

    if not phone:
        raise HTTPException(
            status_code=400,
            detail="Phone number is required"
        )

    conn = get_db_connection()
    cur = None

    try:
        cur = conn.cursor()

        cur.execute("""
            SELECT id
            FROM public.customers
            WHERE phone = %s
        """, (phone,))

        customer = cur.fetchone()

        if customer is None:
            raise HTTPException(
                status_code=404,
                detail="Customer not found"
            )

        customer_id = customer[0]

        # Generate a six-digit OTP.
        otp = str(secrets.randbelow(900000) + 100000)

        # Hash the OTP with the secret key.
        otp_hash = hmac.new(
            OTP_SECRET.encode(),
            otp.encode(),
            hashlib.sha256
        ).hexdigest()

        # Invalidate previous unused OTPs.
        cur.execute("""
            UPDATE public.otp_codes
            SET used = TRUE
            WHERE customer_id = %s
              AND used = FALSE
        """, (customer_id,))

        # Store the new OTP with a five-minute expiry.
        cur.execute("""
            INSERT INTO public.otp_codes
                (customer_id, otp_hash, expires_at, used)
            VALUES
                (%s, %s, NOW() + INTERVAL '5 minutes', FALSE)
        """, (customer_id, otp_hash))

        conn.commit()

        # Local development only.
        # Never log OTPs in production.
        print(f"TEST OTP for {phone}: {otp}")

        return {
            "message": "OTP generated for testing",
            "expires_in_seconds": 300
        }

    except HTTPException:
        conn.rollback()
        raise

    except psycopg2.Error as e:
        conn.rollback()
        print("OTP database error:", repr(e))
        raise HTTPException(
            status_code=500,
            detail="Could not generate OTP"
        )

    finally:
        if cur is not None:
            cur.close()
        conn.close()



# 10. Verify OTP and issue JWT

@app.post("/verify-otp")
def verify_otp(request: OTPVerifyRequest):
    phone = request.phone.strip()
    otp = request.otp.strip()

    if not OTP_SECRET:
        raise HTTPException(
            status_code=500,
            detail="OTP_SECRET is not configured"
        )

    if not JWT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="JWT_SECRET is not configured"
        )

    if not phone:
        raise HTTPException(
            status_code=400,
            detail="Phone number is required"
        )

    if len(otp) != 6 or not otp.isdigit():
        raise HTTPException(
            status_code=400,
            detail="OTP must contain six digits"
        )

    conn = get_db_connection()
    cur = None

    try:
        cur = conn.cursor()

        cur.execute("""
            SELECT id
            FROM public.customers
            WHERE phone = %s
        """, (phone,))

        customer = cur.fetchone()

        if customer is None:
            raise HTTPException(
                status_code=404,
                detail="Customer not found"
            )

        customer_id = customer[0]

        # Find the latest unused, unexpired OTP.
            
        cur.execute("""
            SELECT id, otp_hash, attempts
            FROM public.otp_codes
            WHERE customer_id = %s
              AND used = FALSE
              AND expires_at > NOW()
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            FOR UPDATE
        """, (customer_id,))

        otp_record = cur.fetchone()

        if otp_record is None:
            raise HTTPException(
                status_code=400,
                detail="OTP is invalid or expired"
            )

        otp_id, stored_hash, attempts = otp_record
        if attempts >= 5:
            raise HTTPException(
                status_code=400,
                detail="OTP attempts exceeded; request a new OTP"
            )
    
    
        entered_hash = hmac.new(
            OTP_SECRET.encode(),
            otp.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(stored_hash, entered_hash):
            cur.execute("""
                UPDATE public.otp_codes
                SET attempts = attempts + 1
                WHERE id = %s
            """, (otp_id,))
            conn.commit()
            raise HTTPException(
                status_code=400,
                detail="Incorrect OTP"
            )

        # Mark the OTP as used.
        cur.execute("""
            UPDATE public.otp_codes
            SET used = TRUE
            WHERE id = %s
              AND customer_id = %s
              AND used = FALSE
              AND expires_at > NOW()
        """, (otp_id, customer_id))

        if cur.rowcount != 1:
            raise HTTPException(
                status_code=400,
                detail="OTP has already been used or expired"
            )

        token_payload = {
            "sub": str(customer_id),
            "exp": datetime.now(timezone.utc)
                   + timedelta(minutes=30)
        }

        access_token = jwt.encode(
            token_payload,
            JWT_SECRET,
            algorithm=JWT_ALGORITHM
        )

        conn.commit()

        return {
            "message": "OTP verified successfully",
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in_seconds": 1800
        }

    except HTTPException:
        conn.rollback()
        raise

    except psycopg2.Error as e:
        conn.rollback()
        print("OTP verification database error:", repr(e))
        raise HTTPException(
            status_code=500,
            detail="Could not verify OTP"
        )

    finally:
        if cur is not None:
            cur.close()
        conn.close()


# Approved tools available to the AI model.
CHAT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_records",
            "description": (
                "Search the authenticated customer's invoice records "
                "by invoice number or payment status."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "invoice_number": {
                        "type": "string",
                        "description": "Invoice number to search for"
                    },
                    "payment_status": {
                        "type": "string",
                        "enum": ["paid", "unpaid", "pending", "overdue"],
                        "description": "Payment status to filter by"
                    }
                },
                "required": [],
                "additionalProperties": False
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "add_invoice",
            "description": (
                "Propose a new invoice for the authenticated customer. "
                "Do not create it until the customer explicitly confirms."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "invoice_number": {"type": "string"},
                    "invoice_date": {
                        "type": "string",
                        "description": "Date in YYYY-MM-DD format"
                    },
                    "amount": {"type": "number"},
                    "currency": {"type": "string"},
                    "payment_status": {
                        "type": "string",
                        "enum": ["paid", "unpaid", "pending", "overdue"]
                    }
                },
                "required": [
                    "invoice_number",
                    "invoice_date",
                    "amount",
                    "currency",
                    "payment_status"
                ],
                "additionalProperties": False
            }
        }
    }
]

def execute_search_records(
    cur,
    customer_id: int,
    arguments: dict
):
    invoice_number = arguments.get("invoice_number")
    payment_status = arguments.get("payment_status")

    if invoice_number is not None:
        invoice_number = invoice_number.strip()
        if not invoice_number:
            raise ValueError("Invoice number cannot be empty")

    if payment_status is not None:
        if payment_status not in {
            "paid", "unpaid", "pending", "overdue"
        }:
            raise ValueError("Invalid payment status")

    if not invoice_number and not payment_status:
        raise ValueError(
            "Provide an invoice number or payment status"
        )

    cur.execute("""
        SELECT id, invoice_number, invoice_date,
               amount, currency, payment_status
        FROM public.invoices
        WHERE customer_id = %s
          AND (%s IS NULL OR invoice_number = %s)
          AND (%s IS NULL OR payment_status = %s)
        ORDER BY invoice_date, invoice_number
        LIMIT 20
    """, (
        customer_id,
        invoice_number, invoice_number,
        payment_status, payment_status
    ))

    rows = cur.fetchall()

    return [
        {
            "invoice_id": row[0],
            "invoice_number": row[1],
            "invoice_date": row[2].isoformat(),
            "amount": str(row[3]),
            "currency": row[4],
            "payment_status": row[5]
        }
        for row in rows
    ]

def execute_add_invoice(
    cur,
    customer_id: int,
    arguments: dict
):
    required_fields = [
        "invoice_number",
        "invoice_date",
        "amount",
        "currency",
        "payment_status"
    ]

    if not all(
        field in arguments
        for field in required_fields
    ):
        raise ValueError("All invoice fields are required")

    invoice_number = arguments["invoice_number"].strip()
    currency = arguments["currency"].strip().upper()
    payment_status = arguments["payment_status"]

    if not invoice_number or not currency:
        raise ValueError("Invoice number and currency are required")

    try:
        invoice_date = datetime.strptime(
            arguments["invoice_date"], "%Y-%m-%d"
        ).date()
        amount = float(arguments["amount"])
    except (ValueError, TypeError):
        raise ValueError("Invalid invoice date or amount")

    if amount <= 0:
        raise ValueError("Invoice amount must be positive")

    if payment_status not in {
        "paid", "unpaid", "pending", "overdue"
    }:
        raise ValueError("Invalid payment status")

    cur.execute("""
        SELECT id
        FROM public.invoices
        WHERE customer_id = %s
          AND invoice_number = %s
    """, (customer_id, invoice_number))

    if cur.fetchone():
        raise ValueError("This invoice number already exists")

    return {
        "invoice_number": invoice_number,
        "invoice_date": invoice_date.isoformat(),
        "amount": amount,
        "currency": currency,
        "payment_status": payment_status
    }

def ask_ollama_with_tools(messages):
    response = requests.post(
        OLLAMA_URL,
        json={
            "model": OLLAMA_MODEL,
            "messages": messages,
            "tools": CHAT_TOOLS,
            "stream": False
        },
        timeout=120
    )

    response.raise_for_status()
    return response.json()["message"]

# 11. AI chat + database message history


@app.post("/chat")
def chat(
    request: ChatMessageRequest,
    customer_id: int = Depends(get_current_customer)
):
    message = request.message.strip()

    if not message:
        raise HTTPException(
            status_code=400,
            detail="Message cannot be empty"
        )

    conn = get_db_connection()
    cur = None

    try:
        cur = conn.cursor()

        # 1. Create a new conversation or verify ownership.
        if request.conversation_id is None:
            cur.execute("""
                INSERT INTO public.conversations (customer_id)
                VALUES (%s)
                RETURNING id
            """, (customer_id,))

            conversation_id = cur.fetchone()[0]

        else:
            cur.execute("""
                SELECT id
                FROM public.conversations
                WHERE id = %s
                  AND customer_id = %s
            """, (request.conversation_id, customer_id))

            conversation = cur.fetchone()

            if conversation is None:
                raise HTTPException(
                    status_code=404,
                    detail="Conversation not found"
                )

            conversation_id = conversation[0]

        # 2. Save the user's message.
        cur.execute("""
            INSERT INTO public.messages
                (conversation_id, customer_id, role, content)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (conversation_id, customer_id, "user", message))

        user_message_id = cur.fetchone()[0]

   
    
        # 3. Prepare invoice-related context.
        invoice_context = "No invoice records were found."
        invoices = []

        invoice_keywords = (
            "invoice", "invoices", "bill", "bills",
            "payment", "paid", "unpaid",
            "pending", "overdue"
        )

        lower_message = message.lower()
        is_invoice_question = any(
            word in lower_message
            for word in invoice_keywords
        )

        if is_invoice_question:
            cur.execute("""
                SELECT id, invoice_number, invoice_date,
                       amount, currency, payment_status
                FROM public.invoices
                WHERE customer_id = %s
                ORDER BY invoice_date, invoice_number
            """, (customer_id,))

            invoices = cur.fetchall()

            

            if invoices:
                invoice_context = "\n".join(
                    f"Invoice ID: {inv[0]}, "
                    f"Invoice number: {inv[1]}, "
                    f"Date: {inv[2]}, "
                    f"Amount: {inv[4]} {inv[3]}, "
                    f"Payment status: {inv[5]}"
                    for inv in invoices
                )

        # 4. Retrieve relevant invoice documents from Qdrant.
        # PostgreSQL remains the source of truth for invoice facts.
        rag_context = "No relevant invoice documents were retrieved."

        if is_invoice_question:
            try:
                from rag import search_customer_invoices

                rag_results = search_customer_invoices(
                    question=message,
                    customer_id=customer_id,
                    limit=5
                )

                if rag_results:
                    rag_context = "\n".join(
                        f"Invoice ID: {item['invoice_id']}, "
                        f"Invoice number: {item['invoice_number']}, "
                        f"Details: {item['text']}"
                        for item in rag_results
                    )

            except Exception as rag_error:
                # Chat can still use verified PostgreSQL records.
                print(
                    "RAG retrieval error:",
                    type(rag_error).__name__
                )

        # 5. Build the system message for Ollama.
        system_message = (
            "You are a helpful customer support assistant. "
            "Answer the customer's actual question directly, "
            "politely, and clearly. "
            "For invoice questions, PostgreSQL records supplied "
            "below are the authoritative source of truth. "
            "Use Qdrant retrieval only as supporting context. "
            "Never invent invoice numbers, IDs, amounts, dates, "
            "currencies, or payment statuses. "
            "Include the invoice ID when reporting invoice facts. "
            "Never reveal another customer's private information. "
            "For general questions, answer normally and do not "
            "mention invoices unless relevant. "
            "If the required information is unavailable, say so.\n\n"
            f"Verified PostgreSQL invoice records:\n"
            f"{invoice_context}\n\n"
            f"Relevant Qdrant retrieval context:\n"
            f"{rag_context}"
        )

       
        if is_invoice_question and invoices:
            requested_invoice_number = None

            # Find an invoice number such as INV-001.
            for word in message.upper().split():
                cleaned_word = word.strip(
                    ".,?!:;()[]{}\"'"
                )

                if (
                    cleaned_word.startswith("INV-")
                    and cleaned_word[4:].isdigit()
                ):
                    requested_invoice_number = cleaned_word
                    break

            # Identify the payment status requested.
            if "unpaid" in lower_message:
                requested_statuses = ["unpaid"]
            else:
                status_keywords = (
                    "paid", "pending", "overdue"
                )
                requested_statuses = [
                    status
                    for status in status_keywords
                    if status in lower_message
                ]

            # Start with this customer's invoices.
            filtered_invoices = invoices

            if requested_invoice_number:
                filtered_invoices = [
                    inv for inv in filtered_invoices
                    if str(inv[1]).upper()
                    == requested_invoice_number
                ]

            if requested_statuses:
                filtered_invoices = [
                    inv for inv in filtered_invoices
                    if str(inv[5]).lower()
                    in requested_statuses
                ]
                # Filter invoices by requested minimum amount.
           
            # Filter invoices by amount.
            import re

            amount_match = re.search(
                r"(above|over|under|below)\s+(?:₹|rs\.?\s*)?(\d+(?:\.\d+)?)",
                lower_message
            )

            if amount_match:
                operator = amount_match.group(1)
                amount_limit = float(amount_match.group(2))

                if operator in ("above", "over"):
                    filtered_invoices = [
                        inv for inv in filtered_invoices
                        if float(inv[3]) > amount_limit
                    ]
                else:
                    filtered_invoices = [
                        inv for inv in filtered_invoices
                        if float(inv[3]) < amount_limit
                    ]


            # Always assign a reply.
            if not filtered_invoices:
                if requested_invoice_number:
                    reply = (
                        "I couldn't find a matching invoice: "
                        f"{requested_invoice_number}."
                    )
                elif requested_statuses:
                    reply = (
                        "I couldn't find invoices with payment "
                        "status: "
                        + ", ".join(requested_statuses)
                        + "."
                    )
                else:
                    reply = "No matching invoices were found."
            else:
                reply = (
                    "Here are your matching invoice records:\n"
                    + "\n".join(
                        f"Invoice ID: {inv[0]} | "
                        f"Invoice: {inv[1]} | "
                        f"Date: {inv[2]} | "
                        f"Amount: {inv[4]} {inv[3]} | "
                        f"Status: {inv[5]}"
                        for inv in filtered_invoices
                    )
                )
        elif is_invoice_question:
            reply = (
                "I couldn't find invoice records for your account."
            )

        else:
            # 7. Use Ollama for general questions.
            try:
                response = requests.post(
                    OLLAMA_URL,
                    json={
                        "model": OLLAMA_MODEL,
                        "messages": [
                            {
                                "role": "system",
                                "content": system_message
                            },
                            {
                                "role": "user",
                                "content": message
                            }
                        ],
                        "stream": False
                    },
                    timeout=120
                )

                response.raise_for_status()
                data = response.json()
                reply = data["message"]["content"]

            except (
                requests.RequestException,
                KeyError,
                TypeError,
                ValueError
            ) as model_error:
                conn.rollback()
                print(
                    "Ollama request error:",
                    type(model_error).__name__
                )
                raise HTTPException(
                    status_code=502,
                    detail="Could not get a response from the AI model"
                )
        

        # 8. Save the assistant's reply.
        cur.execute("""
            INSERT INTO public.messages
                (conversation_id, customer_id, role, content)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (conversation_id, customer_id, "assistant", reply))

        assistant_message_id = cur.fetchone()[0]

        conn.commit()

        return {
            "message": "Chat processed successfully",
            "conversation_id": conversation_id,
            "user_message_id": user_message_id,
            "assistant_message_id": assistant_message_id,
            "reply": reply
        }

    except HTTPException:
        conn.rollback()
        raise

    except psycopg2.Error as db_error:
        conn.rollback()

        print(
            "Chat database error:",
            type(db_error).__name__
        )

        raise HTTPException(
            status_code=500,
            detail="Could not save chat message"
        )

    finally:
        if cur is not None:
            cur.close()

        conn.close()


# 12. Retrieve chat history


@app.get("/chat/{conversation_id}")
def get_chat_history(
    conversation_id: int,
    customer_id: int = Depends(get_current_customer)
):
    conn = get_db_connection()
    cur = None

    try:
        cur = conn.cursor()

        # 1. Verify that this conversation belongs to the customer.
        cur.execute("""
            SELECT id
            FROM public.conversations
            WHERE id = %s
              AND customer_id = %s
        """, (conversation_id, customer_id))

        if cur.fetchone() is None:
            raise HTTPException(
                status_code=404,
                detail="Conversation not found"
            )

        # 2. Retrieve only this customer's messages.
        cur.execute("""
            SELECT id, role, content, created_at
            FROM public.messages
            WHERE conversation_id = %s
              AND customer_id = %s
            ORDER BY created_at, id
        """, (conversation_id, customer_id))

        rows = cur.fetchall()

        return {
            "conversation_id": conversation_id,
            "messages": [
                {
                    "message_id": row[0],
                    "role": row[1],
                    "content": row[2],
                    "created_at": (
                        row[3].isoformat()
                        if row[3] is not None
                        else None
                    )
                }
                for row in rows
            ]
        }

    except HTTPException:
        raise

    except psycopg2.Error as db_error:
        print(
            "Chat history database error:",
            type(db_error).__name__
        )

        raise HTTPException(
            status_code=500,
            detail="Could not retrieve chat history"
        )

    finally:
        if cur is not None:
            cur.close()

        conn.close()