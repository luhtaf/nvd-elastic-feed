import traceback, json, requests, time, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from elasticsearch import Elasticsearch
from queue import Queue
import signal
import sys
import yaml
from tqdm import tqdm

def load_config():
    """
    Load configuration from cron_config.yaml
    """
    try:
        with open('config.yaml', 'r') as config_file:
            return yaml.safe_load(config_file)
    except FileNotFoundError:
        print("Error: Configuration file 'config.yaml' not found. Please copy from 'cron_config.yaml.example'.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing configuration file: {e}")
        sys.exit(1)
config = load_config()
url_elastic = config.get('url_elastic', 'http://localhost:9200')
# Configuration variables
MAX_CONCURRENT_THREADS = 5
THREAD_SPAWN_INTERVAL = 10  # seconds
PER_PAGE = 2000

# Global variables for thread management
page_counter = 1
page_lock = threading.Lock()
total_results = None
shutdown_event = threading.Event()
active_threads = 0
threads_lock = threading.Lock()
progress_bars = {}
progress_lock = threading.Lock()

def log_exception(e, filename="error_log.txt"):
    lineno = e.__traceback__.tb_lineno
    tb_str = traceback.format_exc()
    
    # Thread-safe logging
    with threading.Lock():
        with open(filename, "a") as f:
            f.write(f"[Thread-{threading.current_thread().name}] Exception di line {lineno}:\n")
            f.write(tb_str)
            f.write("\n\n")
        print(f"[Thread-{threading.current_thread().name}] [!] Exception di line {lineno}, lihat {filename}")

template_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=<halaman>"
template_index = "list-cve-new-<tahun>"
es = Elasticsearch(url_elastic, verify_certs=False)

def process_per_page(page, perPage=PER_PAGE):
    """Process a single page of CVE data - thread-safe version with progress bar"""
    thread_name = threading.current_thread().name
    offset = (page-1) * perPage
    url = template_url.replace("<halaman>", str(offset))
    
    # Create progress bar for this thread
    with progress_lock:
        pbar = tqdm(total=perPage, desc=f"Thread-{thread_name[-1]} Page-{page}", 
                   position=len(progress_bars), leave=True, 
                   bar_format='{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]')
        progress_bars[thread_name] = pbar
    
    try:
        pbar.set_description(f"Thread-{thread_name[-1]} Page-{page} [Fetching API]")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        log_exception(e)
        pbar.set_description(f"Thread-{thread_name[-1]} Page-{page} [FAILED]")
        pbar.close()
        with progress_lock:
            del progress_bars[thread_name]
        return None

    vulnerabilities = data.get('vulnerabilities', [])
    processed_count = 0
    total_vulns = len(vulnerabilities)
    
    # Update progress bar total to actual number of vulnerabilities
    pbar.total = total_vulns
    pbar.refresh()
    
    for i, vuln in enumerate(vulnerabilities):
        try:
            _id = vuln['cve']['id']
            newData = {
                "desc": vuln['cve']["descriptions"][0]['value'],
                "published": vuln['cve']['published'],
                "lastModified": vuln['cve']['lastModified'],
                "vulnStatus": vuln['cve']['vulnStatus']
            }

            metrics = vuln["cve"].get("metrics", {})

            # ==== v4 ====
            newData['v4'] = {}
            try:
                cvss_v4 = metrics.get("cvssMetricV4", [])[0]["cvssData"]
                newData['v4']['score'] = cvss_v4["baseScore"]
                newData['v4']['sev'] = metrics.get("cvssMetricV4", [])[0]["baseSeverity"]
                newData['v4']['source'] = "v4.0"
            except Exception as e:
                log_exception(e)

            # ==== v3 ====
            newData['v3'] = {}
            try:
                cvss_v3_1 = metrics.get("cvssMetricV31", [])
                if cvss_v3_1:
                    cvss_v3 = cvss_v3_1[0]["cvssData"]
                    newData['v3']['score'] = cvss_v3["baseScore"]
                    newData['v3']['sev'] = cvss_v3_1[0]["baseSeverity"]
                    newData['v3']['source'] = "v3.1"
                else:
                    cvss_v3_0 = metrics.get("cvssMetricV30", [])
                    if cvss_v3_0:
                        cvss_v3 = cvss_v3_0[0]["cvssData"]
                        newData['v3']['score'] = cvss_v3["baseScore"]
                        newData['v3']['sev'] = cvss_v3_0[0]["baseSeverity"]
                        newData['v3']['source'] = "v3.0"
            except Exception as e:
                log_exception(e)

            # ==== v2 ====
            newData['v2'] = {}
            try:
                cvss_v2 = metrics.get("cvssMetricV2", [])
                if cvss_v2:
                    cvss_v2_data = cvss_v2[0]["cvssData"]
                    newData['v2']['score'] = cvss_v2_data["baseScore"]
                    newData['v2']['sev'] = cvss_v2[0]["baseSeverity"]
                    newData['v2']['source'] = "v2"
            except Exception as e:
                log_exception(e)

            # ==== pilih score utama ====
            newData['score'] = None
            newData['sev'] = None
            newData['source'] = None
            try:
                for ver in ['v4', 'v3', 'v2']:
                    if newData.get(ver) and newData[ver].get('score') is not None:
                        newData['score'] = newData[ver]['score']
                        newData['sev'] = newData[ver]['sev']
                        newData['source'] = ver if ver != 'v3' else newData['v3'].get('source')
                        break
            except Exception as e:
                log_exception(e)

            # bikin index dari tahun CVE
            tahun = _id.split('-')[1]
            index = template_index.replace("<tahun>", tahun)

            res = es.index(index=index, body=newData, id=_id)
            processed_count += 1
            
            # Update progress bar
            pbar.update(1)
            pbar.set_description(f"Thread-{thread_name[-1]} Page-{page} [Processing: {_id}]")
            
        except Exception as e:
            log_exception(e)
            pbar.update(1)
            continue
    
    # Complete progress bar
    pbar.set_description(f"Thread-{thread_name[-1]} Page-{page} [COMPLETED - {processed_count} CVEs]")
    pbar.close()
    
    # Remove from active progress bars
    with progress_lock:
        if thread_name in progress_bars:
            del progress_bars[thread_name]
    
    return data

def get_next_page():
    """Thread-safe way to get the next page number"""
    global page_counter, total_results
    
    with page_lock:
        if total_results is not None:
            # Check if we've reached the end
            start_index = (page_counter - 1) * PER_PAGE
            if start_index >= total_results:
                return None
        
        current_page = page_counter
        page_counter += 1
        return current_page

def worker_thread():
    """Worker function that processes a single page"""
    global total_results, active_threads
    
    # Get next page to process
    page = get_next_page()
    if page is None:
        return
    
    # Increment active threads counter
    with threads_lock:
        active_threads += 1
    
    try:
        # Process the page
        data = process_per_page(page)
        
        # Update total_results if this is the first successful response
        if data and total_results is None:
            with page_lock:
                if total_results is None:  # Double-check after acquiring lock
                    total_results = data.get("totalResults", 0)
                    print(f"[MAIN] Total results detected: {total_results}")
        
    except Exception as e:
        log_exception(e)
    finally:
        # Decrement active threads counter
        with threads_lock:
            active_threads -= 1

def cleanup_progress_bars():
    """Clean up all active progress bars"""
    with progress_lock:
        for thread_name, pbar in progress_bars.items():
            pbar.set_description(f"{pbar.desc} [INTERRUPTED]")
            pbar.close()
        progress_bars.clear()

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    print("\n[MAIN] Shutdown signal received. Waiting for active threads to complete...")
    cleanup_progress_bars()
    shutdown_event.set()

def main():
    global active_threads
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print(f"[MAIN] Starting multi-threaded NVD to Elasticsearch sync")
    print(f"[MAIN] Max concurrent threads: {MAX_CONCURRENT_THREADS}")
    print(f"[MAIN] Thread spawn interval: {THREAD_SPAWN_INTERVAL} seconds")
    print(f"[MAIN] Records per page: {PER_PAGE}")
    print(f"[MAIN] Press Ctrl+C to stop gracefully")
    
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_THREADS) as executor:
        futures = []
        
        while not shutdown_event.is_set():
            # Check if we should stop (all data processed)
            if total_results is not None:
                start_index = (page_counter - 1) * PER_PAGE
                if start_index >= total_results:
                    print(f"[MAIN] ✅ All data processed. Total results: {total_results}")
                    break
            
            # Submit new worker if we have capacity
            if len(futures) < MAX_CONCURRENT_THREADS:
                future = executor.submit(worker_thread)
                futures.append(future)
                print(f"[MAIN] Started thread for page {page_counter-1}. Active threads: {len(futures)}")
            
            # Clean up completed futures
            completed_futures = []
            for future in futures:
                if future.done():
                    completed_futures.append(future)
                    try:
                        future.result()  # This will raise any exceptions that occurred
                    except Exception as e:
                        log_exception(e)
            
            for future in completed_futures:
                futures.remove(future)
            
            # Wait for the specified interval before spawning next thread
            if not shutdown_event.wait(THREAD_SPAWN_INTERVAL):
                continue
            else:
                break
        
        # Wait for all remaining threads to complete
        print(f"[MAIN] Waiting for {len(futures)} remaining threads to complete...")
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log_exception(e)
    
    # Final cleanup of any remaining progress bars
    cleanup_progress_bars()
    print("[MAIN] ✅ All threads completed. Exiting.")

if __name__ == "__main__":
    main()
