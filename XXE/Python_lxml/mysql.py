# Module Imports
import mariadb
import sys

# Connect to MariaDB Platform
try:
    conn = mariadb.connect(
        user="root",
        password="kali",
        host="127.0.0.1",
        port=3306,
        database="db1"

    ) 

except mariadb.Error as e:
    print(f"Error connecting to MariaDB Platform: {e}")
    sys.exit(1)

cur = conn.cursor() 

#retrieving information 
some_name = "test@test.com" 
cur.execute("SELECT id,email,password FROM users  WHERE email=?", (some_name,)) 

for id, email, password in cur: 
    print(f"id: {id},emailid: {email}, password: {password}")





# Get Cursor
cur = conn.cursor()
