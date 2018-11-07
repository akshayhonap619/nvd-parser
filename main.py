import requests
import re
import psycopg2
from os import listdir
from os.path import isfile, join
import zipfile
import json
import os
from helpers import *

# Go to the NVD seed page and extract the text from the page
rs = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
r_text = rs.text

# Look for all the json zip files
# Store each file in the /data folder
for filename in re.findall("nvdcve-1.0-[a-z0-9]*\.json\.zip",r_text):
    print("Downloaded file")
    print(filename)
    r_file = requests.get("https://static.nvd.nist.gov/feeds/json/cve/1.0/" + filename, stream=True)
    with open("data/" + filename, 'wb') as f:
        for chunk in r_file:
            f.write(chunk)


conn = psycopg2.connect(os.environ['DB_Connection'])
cursor = conn.cursor()

# Get all the files from the /data folder. Sort the files so that we can start from year 2002 and go in order
files = [f for f in listdir("data/") if isfile(join("data/", f))]
files.sort()

# Read each zip file and store it's content in the data variable. It contains all the json data of 1 file
for file in files:
    print("Currently processing file ")
    print(file)
    archive = zipfile.ZipFile(join("data/", file), 'r')
    jsonfile = archive.open(archive.namelist()[0])
    data = json.loads(jsonfile.read())
    jsonfile.close()

    for cve in data['CVE_Items']:
        # Get CVE information from 'cve' key in 'CVE_Items'
        id = cve['cve']['CVE_data_meta']['ID']
        description = cve['cve']['description']['description_data'][0]['value']
        published_data = cve['publishedDate']
        last_modified_data = cve['lastModifiedDate']

        # Extract scores, if not available take None
        base_score_v2 = cve['impact']['baseMetricV2']['cvssV2']['baseScore'] if 'baseMetricV2' in cve[
            'impact'] else None
        base_score_v3 = cve['impact']['baseMetricV3']['cvssV3']['baseScore'] if 'baseMetricV3' in cve[
            'impact'] else None

        # Check if the CVE already exists in database
        cve_id = get_CVE_id(id, cursor)

        # If CVE not present in database insert in db and get it's id from the database
        if cve_id == None:
            cve_id = insert_cve_into_db(id, description, last_modified_data, published_data, base_score_v2,
                                        base_score_v3, cursor)

        # Extract vendor information
        for vendor in cve['cve']['affects']['vendor']['vendor_data']:
            vendor_name = vendor['vendor_name']
            # Check if vendor already exists in db, if yes get the database id
            vendor_id = get_vendor_id(vendor_name, cursor)

            # If vendor doesn't exist,insert in db and get it's database id
            if vendor_id == None:
                vendor_id = insert_vendor_into_db(vendor_name, cursor)

            # Insert into cve_vendor table, which stores information about vendors in a CVE;
            insert_cve_vendor_data(cve_id, vendor_id, cursor)

            # Extract product information
            for product in vendor['product']['product_data']:
                product_name = product['product_name']

                # Insert product into database
                insert_product(product_name, vendor_id, cursor)
                # Get database id for product
                product_id = get_product_id(product_name, cursor)

                ## Inserts into products_in_cve table ; To denote that a product by a vendor is in a CVE
                insert_cve_vendor_product(cve_id, vendor_id, product_id, cursor)

                # Extract version information - (enumerated versions for a product)
                for version in product['version']['version_data']:
                    version_value = version['version_value']
                    # Inserts into cve_affects_product_version table ;
                    # To denote that a version for a product, by a vendor is in a CVE
                    insert_enumerated_version(cve_id, vendor_id, product_id, version_value, cursor)

        # Extract CPE data
        for node in cve['configurations']['nodes']:
            # If there is no 'cpe_match' field, continue as there is no cpe data for the CVE
            if 'cpe_match' not in node:
                continue

            # Extract CPE Uri and extract vendor and product name
            for cpe_match in node['cpe_match']:
                pattern = cpe_match['cpe23Uri'].split(':')
                vendor = pattern[3]
                product = pattern[4]

                # Extract version ranges if present, else None
                versionStartExcluding = cpe_match[
                    'versionStartExcluding'] if 'versionStartExcluding' in cpe_match else None
                versionStartIncluding = cpe_match[
                    'versionStartIncluding'] if 'versionStartIncluding' in cpe_match else None
                versionEndExcluding = cpe_match['versionEndExcluding'] if 'versionEndExcluding' in cpe_match else None
                versionEndIncluding = cpe_match['versionEndIncluding'] if 'versionEndIncluding' in cpe_match else None

                # Get vendor id from database if exists
                vendor_id = get_vendor_id(vendor, cursor)
                # Else insert in database and get id
                if (vendor_id == None):
                    vendor_id = insert_vendor_into_db(vendor, cursor)

                # Get product id from database if exists, else insert in database
                insert_product(product, vendor_id, cursor)
                product_id = get_product_id(product, cursor)

                # If there is atleast one CPE range present, insert ranges in database
                if (versionStartIncluding != None or versionStartExcluding != None or versionEndIncluding != None
                    or versionEndExcluding != None):
                    insert_cpe_vulnerable_ranges(cve_id, vendor_id, product_id, versionStartIncluding,
                                                 versionStartExcluding, versionEndIncluding, versionEndExcluding,
                                                 cursor)
    # Commit to database after finishing 1 file
    conn.commit()
# Close connection with database
conn.close()