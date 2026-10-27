
from pathlib import Path

from qdrant_client import QdrantClient, models
from sentence_transformers import SentenceTransformer


# --------------------------------------------------
# 1. Project configuration
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
QDRANT_PATH = PROJECT_ROOT / "qdrant_storage"

COLLECTION_NAME = "customer_invoices"
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
VECTOR_SIZE = 384


# --------------------------------------------------
# 2. Load embedding model
# --------------------------------------------------

embedding_model = SentenceTransformer(EMBEDDING_MODEL)


# --------------------------------------------------
# 3. Create a Qdrant client when needed
# --------------------------------------------------

def get_qdrant_client():
    """Open the persistent local Qdrant database."""
    QDRANT_PATH.mkdir(parents=True, exist_ok=True)
    return QdrantClient(path=str(QDRANT_PATH))


# --------------------------------------------------
# 4. Create collection and customer index
# --------------------------------------------------

def create_collection(qdrant):
    """Create collection if missing and index customer_id."""

    if not qdrant.collection_exists(COLLECTION_NAME):
        qdrant.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=models.VectorParams(
                size=VECTOR_SIZE,
                distance=models.Distance.COSINE,
            ),
        )

    qdrant.create_payload_index(
        collection_name=COLLECTION_NAME,
        field_name="customer_id",
        field_schema=models.PayloadSchemaType.INTEGER,
        wait=True,
    )


# --------------------------------------------------
# 5. Convert invoice to searchable text
# --------------------------------------------------

def invoice_to_text(invoice):
    return (
        f"Invoice {invoice['invoice_number']}. "
        f"Date: {invoice['invoice_date']}. "
        f"Amount: {invoice['currency']} {invoice['amount']}. "
        f"Payment status: {invoice['payment_status']}."
    )


# --------------------------------------------------
# 6. Search invoices for one authenticated customer
# --------------------------------------------------

def search_customer_invoices(
    question: str,
    customer_id: int,
    limit: int = 5,
):
    """Search only invoices belonging to the given customer."""

    qdrant = get_qdrant_client()

    try:
        if not qdrant.collection_exists(COLLECTION_NAME):
            return []

        query_vector = embedding_model.encode(
            question
        ).tolist()

        results = qdrant.query_points(
            collection_name=COLLECTION_NAME,
            query=query_vector,
            query_filter=models.Filter(
                must=[
                    models.FieldCondition(
                        key="customer_id",
                        match=models.MatchValue(
                            value=int(customer_id)
                        ),
                    )
                ]
            ),
            limit=limit,
            with_payload=True,
        )

        return [
            {
                "invoice_id": point.payload["invoice_id"],
                "invoice_number": point.payload["invoice_number"],
                "text": point.payload["text"],
                "score": point.score,
            }
            for point in results.points
            if point.payload
            and int(point.payload["customer_id"]) == int(customer_id)
        ]

    finally:
        qdrant.close()


# --------------------------------------------------
# 7. Index all PostgreSQL invoices
# --------------------------------------------------

def index_all_invoices():
    """Index PostgreSQL invoices into persistent Qdrant."""

    from main import get_db_connection

    qdrant = get_qdrant_client()
    conn = None
    cur = None

    try:
        create_collection(qdrant)

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT id, customer_id, invoice_number,
                   invoice_date, amount, currency, payment_status
            FROM public.invoices
            ORDER BY id
        """)

        rows = cur.fetchall()
        indexed_count = 0

        for row in rows:
            (
                invoice_id,
                customer_id,
                invoice_number,
                invoice_date,
                amount,
                currency,
                payment_status,
            ) = row

            invoice = {
                "invoice_number": invoice_number,
                "invoice_date": str(invoice_date),
                "amount": str(amount),
                "currency": currency,
                "payment_status": payment_status,
            }

            text = invoice_to_text(invoice)
            vector = embedding_model.encode(text).tolist()

            qdrant.upsert(
                collection_name=COLLECTION_NAME,
                points=[
                    models.PointStruct(
                        id=int(invoice_id),
                        vector=vector,
                        payload={
                            "customer_id": int(customer_id),
                            "invoice_id": int(invoice_id),
                            "invoice_number": invoice_number,
                            "invoice_date": str(invoice_date),
                            "amount": str(amount),
                            "currency": currency,
                            "payment_status": payment_status,
                            "text": text,
                        },
                    )
                ],
                wait=True,
            )

            indexed_count += 1

        total_points = qdrant.get_collection(
            COLLECTION_NAME
        ).points_count

        print("PostgreSQL invoices:", len(rows))
        print("Invoices indexed:", indexed_count)
        print("Qdrant total points:", total_points)

    finally:
        if cur is not None:
            cur.close()

        if conn is not None:
            conn.close()

        qdrant.close()


# --------------------------------------------------
# 8. Run indexing only when executed directly
# --------------------------------------------------

if __name__ == "__main__":
    index_all_invoices()
