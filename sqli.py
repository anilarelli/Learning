from flask import Flask, request, render_template, render_template_string, redirect, url_for,request, abort
import pymysql
import sys
import os

app = Flask(__name__,template_folder='../templates')

@app.route('/test')
def test():
    return redirect("/welcome")

@app.route('/welcome')
def welcome():
    return render_template('welcome')

def get_db_connection():
    conn = pymysql.connect(
            host="127.0.0.1",
            user="root",
            password="kali",
            database="db1"

    )

    return conn


@app.route('/login', methods=['GET','POST'])

def login():
    error = None
    if request.method =='POST':
           username = request.form['username']
           password = request.form['password']

           query = (f"SELECT * FROM users Where email= '{username}' AND password= '{password}'")

#           query = "SELECT * FROM users Where email= %s AND password= %s "

           conn = get_db_connection()
           cursor = conn.cursor()
           cursor.execute(query)
           user = cursor.fetchone()

           cursor.close()
           conn.close()

           if user:
               return redirect(url_for('test'))


           else:
               error = 'invalid credentials, Please try again.'


    return render_template('/login.html', error=error) 

Allowed_Directory = ["/home/kali/Downloads/", "/home/kali/Documents/"]

@app.route('/lfi')

def view_file():

    filename = request.args.get('file')

#    file_path = os.path.abspath(filename)


#    is_valid_path = any(
#            file_path.startswith(os.path.abspath(whitelisted_dir)) for whitelisted_dir in Allowed_Directory)


#    if not is_valid_path:
#        return "unauthorized access", 403


    try:
        with open(filename, 'r') as file:

            content = file.read()

        return render_template_string(content)
    except FileNotFoundError:
        return "File Not Found", 404
    except Exception as ex:
        print(f'exception is {ex}')
        return ex
    

if __name__ == '__main__':

    app.run(debug=True)
