from flask import Flask, render_template, request
import ibm_db
connectionstring = "DATABASE=bludb;HOSTNAME=21fecfd8-47b7-4937-840d-d791d0218660.bs2io90l08kqb1od8lcg.databases.appdomain.cloud;PORT=31864;PROTOCOL=TCPIP;UID=mzh43207;PWD=pLYMGfSprZntFyaz;SECURITY=SSL;"

connection = ibm_db.connect(connectionstring, '', '')


app = Flask(__name__)


@app.route("/")
def signup():
    return render_template("signup.html")


@app.route("/signup")
def signup1():
    return render_template("signup.html")


@app.route("/home")
def home():
    return render_template("index.html")


@app.route("/signin")
def signin():
    return render_template("signin.html")


@app.route("/aboutus")
def aboutus():
    return render_template("aboutus.html")


@app.route("/adduser", methods=['POST'])
def adduser():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')

        sql = "SELECT * FROM User WHERE email =?"
        stmt = ibm_db.prepare(connection, sql)
        ibm_db.bind_param(stmt, 1, email)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)

    if account:
        return render_template('signup.html', msg="You are already a member, please login using your details")
    else:
        insert_sql = "INSERT INTO User VALUES (?,?,?,?)"
        prep_stmt = ibm_db.prepare(connection, insert_sql)
        ibm_db.bind_param(prep_stmt, 1, first_name)
        ibm_db.bind_param(prep_stmt, 2, last_name)
        ibm_db.bind_param(prep_stmt, 3, email)
        ibm_db.bind_param(prep_stmt, 4, password)
        ibm_db.execute(prep_stmt)
    return render_template('signin.html')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        sql = "SELECT * FROM user WHERE email =?"
        stmt = ibm_db.prepare(connection, sql)
        ibm_db.bind_param(stmt, 1, email)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)

        if account:
            if (password == str(account['PASS']).strip()):
                return render_template('index.html')
            else:
                return render_template('signin.html', msg="Password is invalid")
        else:
            return render_template('signin.html', msg="Email is invalid")
    else:
        return render_template('signin.html')
