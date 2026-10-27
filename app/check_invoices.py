from main import get_db_connection

conn = get_db_connection()
cur = conn.cursor()

cur.execute("""
    SELECT column_name, data_type
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'invoices'
    ORDER BY ordinal_position
""")

for row in cur.fetchall():
    print(row)

cur.close()
conn.close()