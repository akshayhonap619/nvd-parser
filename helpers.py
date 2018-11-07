## Returns the database id for a CVE_id (This CVE_ID is coming from nvd website)
def get_CVE_id(id,cursor) :
    query = """ Select id from "Cve" where cve_id = %s  """
    cursor.execute(query,(id,))
    cve_id = cursor.fetchone()
    if cve_id!= None :
        return cve_id[0]


## Inserts aa new cve in the cve table in the database
def insert_cve_into_db(id, description, last_modified_data, published_data, base_score_v2, base_score_v3,cursor):
    query = """ INSERT INTO "Cve"(cve_id, description, last_modified, published, cvss2_score, cvss3_score) VALUES (%s,%s,%s,%s,%s,%s)  """
    cursor.execute(query, (id, description, last_modified_data, published_data, base_score_v2, base_score_v3))
    return get_CVE_id(id,cursor)


## Gets vendor_id for a given name if it exists in database else returns null
def get_vendor_id(name,cursor) :
    query = """ Select id from vendor where name = %s  """
    cursor.execute(query, (name,))
    vendor_id = cursor.fetchone()
    if (vendor_id != None):
        return vendor_id[0]



## Insert a new vendor in the vendor table and returns the database id of the newly inserted vendor
def insert_vendor_into_db(name,cursor) :
    query = """ INSERT INTO vendor (name) VALUES(%s)"""
    cursor.execute(query, (name,))
    return get_vendor_id(name,cursor)



# Insert in cve_affects_vendor table which stores information about vendors in a CVE;
# On Conflict Do Nothing, because we have already inserted that same row before, so we can safely ignore it
def insert_cve_vendor_data(cve_id, vendor_id, cursor) :
    query = \
        """ INSERT INTO cve_affects_vendor(cve_id, vendor_id) VALUES (%s, %s)
                ON CONFLICT DO NOTHING """
    cursor.execute(query, (cve_id, vendor_id))



# Inserts a new products in the database
# If it already exists, does nothing as product_name and vendor_id is unique
def insert_product(product_name, vendor_id, cursor) :
    query = """ INSERT INTO product(name,vendor_id) VALUES (%s,%s)
                            ON CONFLICT DO NOTHING """
    cursor.execute(query, (product_name, vendor_id))


# Gets the database id for a product name
def get_product_id(product_name,cursor) :
    query = """SELECT id from product where name = %s  """
    cursor.execute(query, (product_name,))
    return cursor.fetchone()[0]


## Inserts into products_in_cve table ; To denote that a product by a vendor is in a CVE
## On Conflict do nothing as the same exact row already exists in database, we can safely ignore
def insert_cve_vendor_product(cve_id,vendor_id, product_id,cursor):
    query = """ INSERT INTO products_in_cve (cve_id,vendor_id,product_id) VALUES(%s,%s,%s)
                             ON CONFLICT DO NOTHING """
    cursor.execute(query, (cve_id, vendor_id, product_id))


## Inserts into cve_affects_product_version table ;
## To denote that a version for a product, by a vendor is in a CVE
## On Conflict do nothing as the same exact row already exists in database, we can safely ignore
def insert_enumerated_version(cve_id, vendor_id, product_id, version_value,cursor) :
    query = """INSERT INTO cve_affects_product_version(cve_id,vendor_id,product_id,version)
                                VALUES(%s,%s,%s,%s)  ON CONFLICT DO NOTHING  """
    cursor.execute(query, (cve_id, vendor_id, product_id, version_value))


## Inserts into cpe_version_ranges_for_cve_vulnerable_products table ;
## To denote the range of vulnerable products, by a vendor is in a CVE defined by CPE
## On Conflict do nothing as the same exact row already exists in database, we can safely ignore
def insert_cpe_vulnerable_ranges(cve_id, vendor_id, product_id, version_start_including, version_start_excluding,
                                 version_end_including,version_end_excluding,cursor):
    query = """INSERT INTO cpe_version_ranges_for_cve_vulnerable_products(
    	                    cve_id, vendor_id, product_id, version_start_including, version_start_excluding, version_end_including, version_end_excluding)
    	                    VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING"""
    cursor.execute(query, (
                    cve_id, vendor_id, product_id, version_start_including, version_start_excluding,
                                 version_end_including,version_end_excluding))
