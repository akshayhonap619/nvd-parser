import json
import psycopg2
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
cursor.execute(query)

conn.commit()

