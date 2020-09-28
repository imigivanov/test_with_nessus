import requests
import time
from datetime import date
import pandas


def request_report():
    payload = {
        "format": "csv"
    }
    request_url = "{}/{}/export".format(basic_url, SCAN_ID)
    response = requests.request("POST", request_url, json=payload, headers=headers, verify=False).json()
    return response['file']


def ready_to_download(file_id):
    request_url = "{}/{}/export/{}/status".format(basic_url, SCAN_ID, file_id)
    response = requests.request("GET", request_url, headers=headers, verify=False).json()
    return response['status'] == "ready"


def download_file(file_id):
    request_url = "{}/{}/export/{}/download".format(basic_url, SCAN_ID, file_id)
    local_filename = "scan_results_{}.csv".format(date.today().strftime("%d_%m_%Y"))
    with requests.get(request_url, headers=headers, stream=True, verify=False) as r:
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

    ACCESS_KEY = '79a2f897f56b2896f9e75d8d32e3238698f182763dad935390723a1a174e7d54'
    SECRET_KEY = '520e15f293b72e10a2afcbd5cb1b5854be69ecfff0a6fc144a4c168b439bd1f6'
    SCAN_ID = 11

    basic_url = "https://localhost:8834/scans"

    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "X-ApiKeys": "accessKey={}; secretKey={}".format(ACCESS_KEY, SECRET_KEY)
    }

    file_id = request_report()

    while True:

        time.sleep(2)
        if not ready_to_download(file_id):
            continue

        break

    plugins = get_list_of_pkg_to_fix(download_file(file_id))
    filter = plugins["Solution"].str.contains('Update the affected ?.* packages.')
    result_dict = plugins.where(filter).dropna().to_dict()
    print("Results of scan:\n")
    for i in result_dict["Solution"]:
        print("{} - {} - {}\n\n".format(result_dict["Host"][i], result_dict["Plugin Output"][i], result_dict["CVE"][i]))
