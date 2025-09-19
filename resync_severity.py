import sys
import traceback
import time
import warnings
from datetime import datetime
from elasticsearch import Elasticsearch, NotFoundError
from tqdm import tqdm
from elasticsearch.helpers import scan, bulk

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

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
    url_elastic = "https://admin:admin123@10.12.20.213:9200"
    es = Elasticsearch(
        [url_elastic], 
        verify_certs=False, 
        request_timeout=120,      # Increased timeout to 120s
        retry_on_timeout=True,    # Automatically retry on timeout
        max_retries=5,            # Increased retries
        sniff_on_start=False,     # Disable sniffing on start
        sniff_on_connection_fail=False, # Disable sniffing on fail
        sniffer_timeout=None,
        http_compress=True,       # Enable compression
        timeout=30                # Connection timeout
    )
    
    # Test connection first
    print(f"[*] Testing connection to Elasticsearch...")
    try:
        # Simple ping test
        if not es.ping():
            print("[!] Elasticsearch is not responding to ping")
            sys.exit(1)
        
        # Get cluster info
        cluster_info = es.info()
        print(f"[*] Connected to Elasticsearch cluster: {cluster_info.get('cluster_name', 'Unknown')}")
        print(f"[*] Elasticsearch version: {cluster_info.get('version', {}).get('number', 'Unknown')}")
        
    except Exception as e:
        print(f"[!] Failed to connect to Elasticsearch: {e}")
        print(f"[!] Please check:")
        print(f"    - Elasticsearch server is running")
        print(f"    - URL is correct: {url_elastic}")
        print(f"    - Network connectivity")
        print(f"    - Authentication credentials")
        sys.exit(1)

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
    actions_for_bulk = []
    BULK_BATCH_SIZE = 500 # How many updates to send in one bulk request

    try:
        # Get the total count for the progress bar
        print(f"[*] Discovering indices matching pattern '{index_pattern}'...")
        try:
            # The 'expand_wildcards' option is crucial here.
            indices = es.indices.get(index=index_pattern, expand_wildcards="open")
            target_indices = sorted(list(indices.keys()))
            print(f"[*] Found {len(target_indices)} indices to process.")
            if not target_indices:
                print("[*] No documents found in the specified time range. Exiting.")
                sys.exit(0)
            
            total_docs = es.count(index=index_pattern, body=query)['count']
            print(f"[*] Found {total_docs} documents to process.")

        except Exception as e:
            print(f"\n[!] Failed to get indices for pattern '{index_pattern}'. Error: {e}")
            sys.exit(1)

        # Use scan helper to efficiently scroll through all results
        with tqdm(total=total_docs, desc="Processing documents", unit=" docs") as pbar:
            for doc in scan(es, index=index_pattern, query=query, size=500, scroll='5m'):
                try:
                    doc_id = doc['_id']
                    index_name = doc['_index']
                    cve_id = doc['_source'].get('Vuln')

                    if not cve_id:
                        skipped_count += 1
                        pbar.update(1)
                        continue

                    new_score, new_severity = get_cve_details(es, cve_id)

                    if new_score is not None and new_severity is not None:
                        if (doc['_source'].get('Score') != new_score or
                            doc['_source'].get('Severity') != new_severity):
                            
                            action = {
                                "_op_type": "update",
                                "_index": index_name,
                                "_id": doc_id,
                                "doc": {"Score": new_score, "Severity": new_severity}
                            }
                            actions_for_bulk.append(action)
                        else:
                            skipped_count += 1  # Already up-to-date
                    else:
                        skipped_count += 1  # CVE details not found

                    # Perform bulk update when batch size is reached
                    if len(actions_for_bulk) >= BULK_BATCH_SIZE:
                        success, _ = bulk(es, actions_for_bulk, raise_on_error=True)
                        updated_count += success
                        actions_for_bulk = [] # Reset batch

                except Exception as e:
                    error_count += 1
                    log_exception(e, doc.get('_source', {}).get('Vuln', 'N/A'), doc.get('_id', 'N/A'))
                finally:
                    pbar.update(1)

        # Perform final bulk update for any remaining actions
        if actions_for_bulk:
            success, _ = bulk(es, actions_for_bulk, raise_on_error=True)
            updated_count += success

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