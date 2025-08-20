import traceback, json, requests, yaml
from elasticsearch import Elasticsearch
def log_exception(e, filename="error_log.txt"):
    lineno = e.__traceback__.tb_lineno
    tb_str = traceback.format_exc()
    with open(filename, "a") as f:
        f.write(f"Exception di line {lineno}:\n")
        f.write(tb_str)
        f.write("\n\n")
    print(f"[!] Exception di line {lineno}, lihat {filename}")

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
template_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=<halaman>"
template_index = "list-cve-new-<tahun>"
es = Elasticsearch(url_elastic, verify_certs=False)

def process_per_page(page, perPage=2000):
    offset = (page-1) * perPage
    url = template_url.replace("<halaman>", str(offset))
    print(f"Processing page {page}, offset={offset}")
    
    response = requests.get(url)
    data = response.json()

    vulnerabilities = data.get('vulnerabilities', [])
    for vuln in vulnerabilities:
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
        print(index, "->", _id, newData['score'], newData['sev'])
    
    return data  # balikin untuk tahu totalResults dll


def main():
    page = 1
    perPage = 2000
    while True:
        data = process_per_page(page, perPage)
        total = data.get("totalResults", 0)
        start = data.get("startIndex", 0)
        results = data.get("resultsPerPage", perPage)

        if start + results >= total:
            print("✅ Sudah sampai akhir data")
            break
        page += 1

if __name__ == "__main__":
    main()
