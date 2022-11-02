from flask import Flask, render_template, request
import ibm_db
from flask_mail import Mail, Message
from random import randint
import os
import pathlib
import requests
import tweepy
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

connectionstring = "DATABASE=bludb;HOSTNAME=21fecfd8-47b7-4937-840d-d791d0218660.bs2io90l08kqb1od8lcg.databases.appdomain.cloud;PORT=31864;PROTOCOL=TCPIP;UID=mzh43207;PWD=pLYMGfSprZntFyaz;SECURITY=SSL;"

connection = ibm_db.connect(connectionstring, '', '')
app = Flask(__name__)
mail = Mail(app)
app.secret_key = "HireMe.com"
useremail = ""
newuser = None


app.config["MAIL_SERVER"] = 'smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = '2k19cse052@kiot.ac.in'
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

consumer_key = ''
consumer_secret = ''
tcallback = 'http://127.0.0.1:5000/tcallback'

GOOGLE_CLIENT_ID = ""
client_secrets_file = os.path.join(
    pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


@app.route("/signup")
@app.route("/")
def signup():
    return render_template("signup.html")


@app.route('/verification', methods=["POST", "GET"])
def verify():

    if request.method == 'POST':
        global first_name
        global last_name
        global useremail
        global password
        global email
        global otp

        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        useremail = request.form.get('email')
        password = request.form.get('password')

        sql = "SELECT * FROM User WHERE email =?"
        stmt = ibm_db.prepare(connection, sql)
        ibm_db.bind_param(stmt, 1, useremail)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)

        if (account):
            return render_template('signup.html', msg="You are already a member, please login using your details")

        else:
            otp = randint(000000, 999999)
            email = request.form['email']
            msg = Message(subject='OTP', sender='hackjacks@gmail.com',
                          recipients=[email])
            msg.body = "You have succesfully registered for Hire Me!\nUse the OTP given below to verify your email ID.\n\t\t" + \
                str(otp)
            mail.send(msg)
            return render_template('verification.html')

    if request.method == 'GET':
        otp = randint(000000, 999999)
        msg = Message(subject='OTP', sender='hackjacks@gmail.com',
                      recipients=[email])
        msg.body = "You have succesfully registered for Hire Me!\nUse the OTP given below to verify your email ID.\n\t\t" + \
            str(otp)
        mail.send(msg)
        return render_template('verification.html', resendmsg="OTP has been resent")


@app.route('/validate', methods=['POST'])
def validate():
    global useremail
    user_otp = request.form['otp']
    if otp == int(user_otp):
        insert_sql = "INSERT INTO User(first_name,last_name,email,pass) VALUES (?,?,?,?)"
        prep_stmt = ibm_db.prepare(connection, insert_sql)
        ibm_db.bind_param(prep_stmt, 1, first_name)
        ibm_db.bind_param(prep_stmt, 2, last_name)
        ibm_db.bind_param(prep_stmt, 3, useremail)
        ibm_db.bind_param(prep_stmt, 4, password)
        ibm_db.execute(prep_stmt)
        return render_template('signin.html')

    else:
        return render_template('verification.html', msg="OTP is invalid. Please enter a valid OTP")


@app.route("/googlelogin")
def googlelogin():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(
        session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["email_id"] = id_info.get("email")
    session["first_name"] = id_info.get("given_name")
    session["last_name"] = id_info.get("family_name")

    global first_name
    global last_name
    global useremail
    global password

    first_name = session['first_name']
    last_name = session['last_name']
    useremail = session['email_id']
    password = ""

    sql = "SELECT * FROM User WHERE email =?"
    stmt = ibm_db.prepare(connection, sql)
    ibm_db.bind_param(stmt, 1, useremail)
    ibm_db.execute(stmt)
    account = ibm_db.fetch_assoc(stmt)

    if account:
        if (account['NEWUSER'] == 1):
            return redirect('/profile')
        return redirect('/home')

    else:

        insert_sql = "INSERT INTO User(first_name,last_name,email,pass) VALUES (?,?,?,?)"
        prep_stmt = ibm_db.prepare(connection, insert_sql)
        ibm_db.bind_param(prep_stmt, 1, first_name)
        ibm_db.bind_param(prep_stmt, 2, last_name)
        ibm_db.bind_param(prep_stmt, 3, useremail)
        ibm_db.bind_param(prep_stmt, 4, password)
        ibm_db.execute(prep_stmt)
        return redirect("/profile")


@app.route('/tlogin')
def auth():
    auth = tweepy.OAuthHandler(consumer_key, consumer_secret, tcallback)
    url = auth.get_authorization_url()
    session['request_token'] = auth.request_token
    return redirect(url)


@app.route('/tcallback')
def twitter_callback():

    global first_name
    request_token = session['request_token']
    print(request_token)
    del session['request_token']

    auth = tweepy.OAuthHandler(consumer_key, consumer_secret, tcallback)
    auth.request_token = request_token
    verifier = request.args.get('oauth_verifier')
    auth.get_access_token(verifier)
    session['token'] = (auth.access_token, auth.access_token_secret)
    first_name = session['token']
    return redirect('/profile')


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/signin")


@app.route("/home")
def home():
    return render_template("index.html")


@app.route("/signin")
@app.route("/login", methods=['GET', 'POST'])
def login():
    global useremail
    global newuser
    if request.method == 'POST':
        useremail = request.form.get('email')
        password = request.form.get('password')
        sql = "SELECT * FROM user WHERE email =?"
        stmt = ibm_db.prepare(connection, sql)
        ibm_db.bind_param(stmt, 1, useremail)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)
        newuser = account['NEWUSER']
        if account:
            if (password == str(account['PASS']).strip()):
                # return redirect('/profile')
                if (account['NEWUSER'] == 1):
                    return redirect('/profile')
                return redirect('/home')
            else:
                return render_template('signin.html', msg="Password is invalid")
        else:
            return render_template('signin.html', msg="Email is invalid")
    else:
        return render_template('signin.html')


@app.route("/profile", methods=["POST", "GET"])
def profile():
    global newuser
    global useremail
    global first_name
    if (request.method == "POST"):
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        mobile_no = request.form.get('mobile_no')
        address_line_1 = request.form.get('address_line_1')
        address_line_2 = request.form.get('address_line_2')
        zipcode = request.form.get('zipcode')
        city = request.form.get('city')
        education = request.form.get('education')
        country = request.form.get('countries')
        state = request.form.get('states')
        experience = request.form.get('experience')
        job_title = request.form.get('job_title')

        insert_sql = "INSERT INTO profile VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
        prep_stmt = ibm_db.prepare(connection, insert_sql)
        ibm_db.bind_param(prep_stmt, 1, first_name)
        ibm_db.bind_param(prep_stmt, 2, last_name)
        ibm_db.bind_param(prep_stmt, 3, mobile_no)
        ibm_db.bind_param(prep_stmt, 4, address_line_1)
        ibm_db.bind_param(prep_stmt, 5, address_line_2)
        ibm_db.bind_param(prep_stmt, 6, zipcode)
        ibm_db.bind_param(prep_stmt, 7, city)
        ibm_db.bind_param(prep_stmt, 8, useremail)
        ibm_db.bind_param(prep_stmt, 9, education)
        ibm_db.bind_param(prep_stmt, 10, country)
        ibm_db.bind_param(prep_stmt, 11, state)
        ibm_db.bind_param(prep_stmt, 12, experience)
        ibm_db.bind_param(prep_stmt, 13, job_title)
        ibm_db.execute(prep_stmt)

        insert_sql = "UPDATE USER SET newuser = false WHERE email=?"
        prep_stmt = ibm_db.prepare(connection, insert_sql)
        ibm_db.bind_param(prep_stmt, 1, useremail)
        ibm_db.execute(prep_stmt)
        return render_template('index.html')
    else:
        sql = "SELECT * FROM profile WHERE email_id =?"
        stmt = ibm_db.prepare(connection, sql)
        ibm_db.bind_param(stmt, 1, useremail)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)
        first_name = account['FIRST_NAME']
        last_name = account['LAST_NAME']
        mobile_no = account['MOBILE_NUMBER']
        address_line_1 = account['ADDRESS_LINE_1']
        address_line_2 = account['ADDRESS_LINE_2']
        zipcode = account['ZIPCODE']
        education = account['EDUCATION']
        countries = account['COUNTRY']
        states = account['STATEE']
        city = account['CITY']
        experience = account['EXPERIENCE']
        job_title = account['JOB_TITLE']
        return render_template('profile.html', email=useremail, newuser=newuser, first_name=first_name, last_name=last_name, address_line_1=address_line_1, address_line_2=address_line_2, zipcode=zipcode, education=education, countries=countries, states=states, experience=experience, job_title=job_title, mobile_no=mobile_no, city=city)
