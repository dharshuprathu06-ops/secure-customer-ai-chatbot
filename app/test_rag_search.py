from rag import search_customer_invoices, qdrant

try:
    print("ARUN - invoice search")
    arun_results = search_customer_invoices(
        "What are my unpaid invoices?",
        customer_id=1,
    )
    for item in arun_results:
        print(item)

    print("\nDEEPA - invoice search")
    deepa_results = search_customer_invoices(
        "What are my unpaid invoices?",
        customer_id=2,
    )
    for item in deepa_results:
        print(item)

    arun_ids = {item["invoice_id"] for item in arun_results}
    deepa_ids = {item["invoice_id"] for item in deepa_results}

    print("\nInvoice IDs overlap:", arun_ids & deepa_ids)
    print("Customer filter test completed.")

finally:
    qdrant.close()