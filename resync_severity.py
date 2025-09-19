import sys
import traceback
import time
from datetime import datetime
from elasticsearch import Elasticsearch, NotFoundError
from tqdm import tqdm

def log_exception(e, cve_id, doc_id, filename="resync_error_log.txt"):
    """Logs an exception to a file."""
    lineno = e.__traceback__.tb_lineno
    tb_str = traceback.format_exc()
    with open(filename, "a") as f:
        f.write(f"Exception for CVE '{cve_id}' (Doc ID: {doc_id}) at line {lineno}:\n")
        f.write(tb_str)
        f.write("\n\n")


def get_cve_details(es_client, cve_id):
    """
    Fetches score and severity for a given CVE ID from the list-cve-* indices.
    """
    if not cve_id or not cve_id.startswith('CVE-'):
        return None, None

    try:
        # Extract year to target the correct index
        year = cve_id.split('-')[1]
        cve_index = f"list-cve-{year}"
        
        # Fetch the document from the list-cve index
        response = es_client.get(index=cve_index, id=cve_id, _source=['score', 'sev'])
        
        score = response['_source'].get('score')
        severity = response['_source'].get('sev')
        
        return score, severity
    except NotFoundError:
        # This is expected if the CVE is not in our list-cve index
        return None, None
    except Exception:
        # For other unexpected errors, we also return None to be safe.
        return None, None

def main():
    """
    Main function to resync score and severity for CVEs in a given index pattern and time range.
    """
    # --- User Input ---
    if len(sys.argv) != 4:
        print("Usage: python resync_severity.py <index_pattern> <start_date> <end_date>")
        print("Example: python resync_severity.py \"nasional_cve_new-*\" 2024-01-01 2024-01-31")
        sys.exit(1)

    index_pattern = sys.argv[1]
    start_date_str = sys.argv[2]
    end_date_str = sys.argv[3]

    try:
        # Append time to dates to cover the full days
        start_date = f"{start_date_str}T00:00:00.000Z"
        end_date = f"{end_date_str}T23:59:59.999Z"
        datetime.fromisoformat(start_date.replace('Z', ''))
        datetime.fromisoformat(end_date.replace('Z', ''))
    except ValueError:
        print("Error: Invalid date format. Please use YYYY-MM-DD.")
        sys.exit(1)

    # --- Initialization ---
    url_elastic = "http://admin:admin123@10.12.20.213:9200"
    es = Elasticsearch(
        [url_elastic], 
        verify_certs=False, 
        request_timeout=60,       # Back to 60s, as requests are smaller
        retry_on_timeout=True,    # Automatically retry on timeout
        max_retries=3,
        sniff_on_start=False,     # Disable sniffing on start
        sniff_on_connection_fail=False, # Disable sniffing on fail
        sniffer_timeout=None
    )

    print(f"[*] Starting resync process...")
    print(f"[*] Index Pattern: {index_pattern}")
    print(f"[*] Time Range: {start_date} to {end_date}")

    # --- Elasticsearch Query ---
    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_date,
                                "lte": end_date,
                                "format": "strict_date_optional_time"
                            }
                        }
                    },
                    {
                        "exists": {
                            "field": "Vuln"
                        }
                    }
                ]
            }
        }
    }

    # --- Processing ---
    updated_count = 0
    skipped_count = 0
    error_count = 0
    page_size = 10  # Process 10 documents at a time (very small)
    current_from = 0

    try:
        # 1. Get a list of all indices that match the pattern and time range. This is a lightweight operation.
        print(f"[*] Discovering indices matching pattern '{index_pattern}'...")
        try:
            # The 'expand_wildcards' option is crucial here.
            indices = es.indices.get(index=index_pattern, expand_wildcards="open")
            target_indices = sorted(list(indices.keys()))
            print(f"[*] Found {len(target_indices)} indices to process.")
            if not target_indices:
                print("[*] No matching indices found. Exiting.")
                sys.exit(0)
        except Exception as e:
            print(f"\n[!] Failed to get indices for pattern '{index_pattern}'. Error: {e}")
            sys.exit(1)

        # 2. Iterate over each index one by one.
        for index_name in target_indices:
            print(f"\n--- Processing Index: {index_name} ---")
            current_from = 0
            
            with tqdm(desc=f"Index {index_name}", unit=" docs") as pbar:
                while True: # Loop for pagination within this single index
                    # Fetch one page of results from the current index
                    try:
                        search_response = es.search(
                            track_total_hits=False, 
                            index=index_name,  # IMPORTANT: Use the specific index name
                            body=query,
                            from_=current_from,
                            size=page_size
                        )
                    except Exception as e:
                        print(f"\n[!] Failed to fetch page for index {index_name} at offset {current_from}. Error: {e}")
                        print("[*] Retrying in 10 seconds...")
                        time.sleep(10)
                        continue

                    hits = search_response['hits']['hits']
                    if not hits:
                        # No more documents in this index, move to the next one.
                        break

                    for doc in hits:
                        try:
                            doc_id = doc['_id']
                            cve_id = doc['_source'].get('Vuln')

                            if not cve_id:
                                skipped_count += 1
                                continue

                            new_score, new_severity = get_cve_details(es, cve_id)

                            if new_score is not None and new_severity is not None:
                                if (doc['_source'].get('Score') != new_score or
                                    doc['_source'].get('Severity') != new_severity):
                                    es.update(index=index_name, id=doc_id, body={"doc": {"Score": new_score, "Severity": new_severity}})
                                    updated_count += 1
                                else:
                                    skipped_count += 1  # Already up-to-date
                            else:
                                skipped_count += 1  # CVE details not found

                        except Exception as e:
                            error_count += 1
                            log_exception(e, doc.get('_source', {}).get('Vuln', 'N/A'), doc.get('_id', 'N/A'))
                        finally:
                            pbar.update(1)

                    current_from += len(hits)

    except KeyboardInterrupt:
        print("\n[!] Process interrupted by user.")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred during the main loop: {e}")
        traceback.print_exc()

    # --- Final Summary ---
    print("\n--- Resync Summary ---")
    print(f"Documents Updated: {updated_count}")
    print(f"Documents Skipped (no change, no CVE ID, or not found): {skipped_count}")
    print(f"Errors during processing: {error_count}")
    print("======================")

if __name__ == "__main__":
    main()