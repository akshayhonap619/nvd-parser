import json
import psycopg2
from psycopg2 import sql
from psycopg2 import extensions as pyse

with open("./nvdcve-1.0-modified.json") as f:
    data = json.load(f)

print(data.keys())

desc = data['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
print(desc)

id =  data['CVE_Items'][0]['cve']['CVE_data_meta']['ID'] + ""

conn = psycopg2.connect("dbname=Test user=swiss password=swiss")
cursor = conn.cursor()

print(id)
query = """ INSERT INTO "Cve"(cve_id) VALUES ('%s')  """ % (id)
#data = (id)
#cursor.execute(query)

#conn.commit()
print(len(data['CVE_Items']))

for cve in data['CVE_Items'] :
    id = cve['cve']['CVE_data_meta']['ID']
    description = cve['cve']['description']['description_data'][0]['value']
    published_data = cve['publishedDate']
    last_modified_data = cve['lastModifiedDate']
    base_score_v2 = cve['impact']['baseMetricV2']['cvssV2']['baseScore'] if 'baseMetricV2' in cve['impact'] else None
    base_score_v3 = cve['impact']['baseMetricV3']['cvssV3']['baseScore'] if 'baseMetricV3' in cve['impact'] else None
    query = """ Select cve_id from "Cve" where cve_id = ('%s')  """ % (id)
    cursor.execute(query)
    rows = cursor.fetchall()

    if len(rows)==0 :
        query = """ INSERT INTO "Cve"(cve_id, description, last_modified, published, cvss2_score, cvss3_score) VALUES (%s,%s,%s,%s,%s,%s)  """ #%(id,description)
        cursor.execute(query,(id,description,last_modified_data,published_data,base_score_v2,base_score_v3))

    for vendor in cve['cve']['affects']['vendor']['vendor_data']:
        vendor_name = vendor['vendor_name']
        query = """ Select name from vendor where name = ('%s')  """ % (vendor_name)
        cursor.execute(query)
        rows = cursor.fetchall()

        if len(rows) == 0:
            query= """ INSERT INTO vendor (name) VALUES('%s')""" % (vendor_name)
            cursor.execute(query)

        query = """Select id from "Cve" where cve_id = '%s' """ % (id)
        cursor.execute(query)
        cve_id= cursor.fetchone()

        #print(cve_id[0])

        query = """SELECT id from vendor where name = '%s' """ %(vendor_name)
        cursor.execute(query)
        vendor_id = cursor.fetchone()

        query = """ INSERT INTO cve_affects_vendor(cve_id, vendor_id) VALUES (%s, %s) 
                    ON CONFLICT DO NOTHING """
        cursor.execute(query,(cve_id[0],vendor_id[0]))

        for product in vendor['product']['product_data']:
            product_name = product['product_name']
            query = """ INSERT INTO product(name,vendor_id) VALUES (%s,%s) 
                        ON CONFLICT DO NOTHING """
            cursor.execute(query,(product_name,vendor_id))
            version_data = product['version']['version_data']

            query= """SELECT id from product where name = '%s'  """ % (product_name)
            cursor.execute(query)
            product_id = cursor.fetchone()[0]

            query = """ INSERT INTO products_in_cve (cve_id,vendor_id,product_id) VALUES(%s,%s,%s) 
                         ON CONFLICT DO NOTHING """
            cursor.execute(query,(cve_id,vendor_id,product_id))


            for version in product['version']['version_data'] :
                version_value = version['version_value']
                query = """INSERT INTO cve_affects_product_version(cve_id,vendor_id,product_id,version) 
                            VALUES(%s,%s,%s,%s)  ON CONFLICT DO NOTHING  """
                cursor.execute(query,(cve_id,vendor_id,product_id,version_value))



            #versions = list(map(lambda x: x['version_value'], product['version']['version_data']))



conn.commit()