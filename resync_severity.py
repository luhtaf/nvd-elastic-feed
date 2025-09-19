import sys
import yaml
import traceback
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan, bulk
from tqdm import tqdm

def load_config():
    """
    Load configuration from config.yaml
    """
    try:
        with open('config.yaml', 'r') as config_file:
            return yaml.safe_load(config_file)
    except FileNotFoundError:
        print("Error: Configuration file 'config.yaml' not found. Please create it.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing configuration file: {e}")
        sys.exit(1)

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
    except Exception:
        # Could be NotFoundError or other issues, we can ignore these
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
        request_timeout=60,
        retry_on_timeout=True, # Automatically retry on timeout
        max_retries=3          # Retry up to 3 times
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
    actions = []
    updated_count = 0
    skipped_count = 0
    error_count = 0

    try:
        print("[*] Scanning for documents to process... (Total count is omitted for stability)")
        # Process documents with a progress bar
        # We don't know the total, so the progress bar will show iteration count
        with tqdm(desc="Processing documents", unit=" docs") as pbar:
            for doc in scan(es, index=index_pattern, query=query):
                try:
                    doc_id = doc['_id']
                    index_name = doc['_index']
                    cve_id = doc['_source'].get('Vuln')

                    if not cve_id:
                        skipped_count += 1
                        pbar.update(1)
                        continue

                    # Fetch the correct score and severity
                    new_score, new_severity = get_cve_details(es, cve_id)

                    # If new data is found and it's different, prepare an update action
                    if new_score is not None and new_severity is not None:
                        if (doc['_source'].get('Score') != new_score or 
                            doc['_source'].get('Severity') != new_severity):
                            
                            action = {
                                "_op_type": "update",
                                "_index": index_name,
                                "_id": doc_id,
                                "doc": {
                                    "Score": new_score,
                                    "Severity": new_severity
                                }
                            }
                            actions.append(action)
                            updated_count += 1
                        else:
                            skipped_count += 1 # Already up-to-date
                    else:
                        skipped_count += 1 # CVE details not found in list-cve

                except Exception as e:
                    error_count += 1
                    log_exception(e, cve_id, doc_id)
                finally:
                    pbar.update(1)

        # Perform bulk update if there are actions to be taken
        if actions:
            print(f"\n[*] Found {len(actions)} documents to update. Performing bulk update...")
            success, failed = bulk(es, actions, raise_on_error=False, raise_on_exception=False)
            print(f"[*] Bulk update complete. Success: {success}, Failed: {len(failed)}")
            if failed:
                print(f"[!] Check resync_error_log.txt for details on failed updates.")
                with open("resync_error_log.txt", "a") as f:
                    f.write("\n--- BULK UPDATE FAILURES ---\n")
                    for item in failed:
                        f.write(f"{item}\n")

    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
        traceback.print_exc()

    # --- Final Summary ---
    print("\n--- Resync Summary ---")
    print(f"Documents Updated: {updated_count}")
    print(f"Documents Skipped (no change, no CVE ID, or not found): {skipped_count}")
    print(f"Errors during processing: {error_count}")
    print("======================")

if __name__ == "__main__":
    main()