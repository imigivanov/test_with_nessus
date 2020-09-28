import requests
import time
from datetime import date
import pandas
from config import *

def compile_headers():
    return {
        "accept": "application/json",
        "content-type": "application/json",
        "X-ApiKeys": "accessKey={}; secretKey={}".format(ACCESS_KEY, SECRET_KEY)
    }


def url_requester(method="GET", url=None, payload=None, stream=False, json=True):
    re = requests.request(method, url, json=payload, headers=compile_headers(), stream=stream, verify=False)
    if json:
        return re.json()
    return re


def request_report(scan):
    payload = {
        "format": "csv"
    }
    request_url = "{}/{}/export".format(BASIC_URL, scan)
    response = url_requester(method="POST", url=request_url, payload=payload)
    return response['file']


def ready_to_download(scan, file):
    request_url = "{}/{}/export/{}/status".format(BASIC_URL, scan, file)
    response = url_requester(method="GET", url=request_url)
    return response['status'] == "ready"


def download_file(scan, file):
    request_url = "{}/{}/export/{}/download".format(BASIC_URL, scan, file)
    local_filename = "scan_results_{}.csv".format(date.today().strftime("%d_%m_%Y"))
    with url_requester(method="GET", url=request_url, stream=True, json=False) as r:
        r.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    return local_filename


def get_list_of_pkg_to_fix(filename):
    col_list = ["CVE", "Host", "Solution", "Plugin Output"]
    result = pandas.read_csv(filename, usecols=col_list)

    return result


if __name__ == '__main__':

    BASIC_URL = "https://localhost:8834/scans"

    scan_id = 11

    file_id = request_report(scan_id)

    while True:

        time.sleep(2)
        if not ready_to_download(scan_id, file_id):
            continue

        break

    packages = get_list_of_pkg_to_fix(download_file(scan_id, file_id))
    re_filter = packages["Solution"].str.contains('Update the affected ?.* packages.')
    result_dict = packages.where(re_filter).dropna().to_dict()

    list_for_groomed_output = []
    for i in result_dict["Solution"]:
        dict_to_provide = {
            "host": result_dict["Host"][i],
            "sec_ticket": result_dict["CVE"][i],
            "packages": [
                {
                    "current": result_dict["Plugin Output"][i].strip().split('\n')[0].split(':')[1].strip(),
                    "required": result_dict["Plugin Output"][i].strip().split('\n')[1].split(':')[1].strip()
                }
            ]
        }
        list_for_groomed_output.append(dict_to_provide)

    result_final_output = {"result": list_for_groomed_output}
    print(result_final_output)
