# import the Flask class from the flask module
from flask import Flask, render_template, redirect, url_for, request#, escape
from jinja2 import Environment
import os
import subprocess
import html
#import mariadb
import sys
from lxml import etree
import re

# create the application object
app = Flask(__name__) 
jinja2 = Environment()

# use decorators to link the function to a url
@app.route('/')
def search_page():
    return render_template('/eees.html')  # return a string

@app.route('/test')
def test():
    return redirect("/welcome")


@app.route('/welcome')
def welcome():
    return render_template('welcome')  # render a template


@app.route('/xxe')
def xx_E():
    return render_template('xxe')

# start the server with the 'run()' method
#if __name__ == '__main__':
#    app.run(debug=True)


# Route for handling the login page logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    conn = mariadb.connect(
            user="root",
            password="kali",
            host="127.0.0.1",
            port=3306,
            database="db1"

            )
    cur = conn.cursor()

    
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:

        username = request.form['username']
        password = request.form['password']



        cur.execute("SELECT * FROM users Where email = %s AND password = %s",(username,password))
#        cur.execute(f"SELECT * FROM users Where email = '{username}' AND password = '{password}' ")

        record = cur.fetchone()
        if record:
            return redirect(url_for('test'))
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template('login.html', error=error)  



@app.route('/print')
def xss():

    name =(request.args.get('uname'))
    return f'Hello {name}, Welome to flask'


@app.route("/unsubscribe")
def page():
    email= html.escape(request.values.get('email'))
    output = jinja2.from_string('<h1>Are you sure you want to unsubscribe this user  ' + email +  '?<h1>' +
                                '<button onclick="unsubscribeUser()" style="margin-right: 1rem;">Unsubscribe</button>' +
                                '<a href="/">Cancel</a>').render()
    return output







@app.route('/ping', methods=['GET'])
def ping():

    address = request.args.get('address','')

    command = f'ping -c 1 {address}'
    result = os.popen(command).read()



#    result = subprocess.run(['ping', '-c', '1', address], capture_output=True, text=True, check=True)
#    output = result.stdout

    return f'<pre>{result}</pre>'






@app.route('/xxe', methods=['POST'])
def parse_xml():

    xml_data = request.form.get('xmlData','')

    if "anil" in xml_data:
        raise ValueError("your attacks are too direct")

#    if re.search(r'<!ENTITY\s+.*\s+SYSTEM\s+["\']', xml_data, re.IGNORECASE):
#        raise ValueError("XXE Detected and blocked.")


    try:
        parser = etree.XMLParser(load_dtd=True, no_network=False, resolve_entities=True)
    
        root = etree.fromstring(xml_data, parser)
        response_content = etree.tostring(root, pretty_print=True,  encoding='unicode')
        return f"Parsed xml :<pre>{response_content}</pre>"
    except Exception as e:
        print(f"Error: {e}")

    








if __name__ == '__main__':
    app.run(debug=True)
















