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

for cve in data['CVE_Items'] :
    id = cve['cve']['CVE_data_meta']['ID']
    description = cve['cve']['description']['description_data'][0]['value']
    print(description+"\n\n")

    query = """ Select cve_id from "Cve" where cve_id = ('%s')  """ % (id)
    cursor.execute(query)
    rows = cursor.fetchall()

#    if len(rows)==0 :
#        query = """ INSERT INTO "Cve"(cve_id,description) VALUES (%s,%s)  """ #%(id,description)
#       cursor.execute(query,(id,description))


query = """ INSERT INTO "Cve"(cve_id,description) VALUES (%s,%s)  """
cursor.execute(query,(123,None))

conn.commit()