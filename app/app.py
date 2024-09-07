import json

import bcrypt
import unicodedata
import os
import pymysql

import pathlib
from random import randint

import google.auth.transport.requests
import requests
from flask import Flask, abort, redirect, render_template, request, session, jsonify
from flask_mail import Mail, Message
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol

dbserver = 'localhost'
dbname = 'hireme'
dbusername = 'root'
dbpassword = ''
conn = pymysql.connect(host=dbserver, user=dbusername,
                       password=dbpassword, database=dbname, cursorclass=pymysql.cursors.DictCursor, port=3306)

cursor = conn.cursor()
app = Flask(__name__)
app.debug = True


def remove_control_characters(s):
    return "".join(ch for ch in s if unicodedata.category(ch)[0] != "C")


mail = Mail(app)
app.secret_key = "HireMe.com"

first_name = ""
last_name = ""
password = ""

app.config["MAIL_SERVER"] = 'smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = '2k19cse052@kiot.ac.in'
app.config['MAIL_PASSWORD'] = os.environ['MAIL_PASSWORD']
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = os.environ['GOOGLE_CLIENT_ID']
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
    global first_name
    global last_name
    global password
    global otp

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        password = str(bcrypt.hashpw(request.form.get('password').encode('utf-8'), bcrypt.gensalt()))
        useremail = request.form.get('email')
        sql = "SELECT * FROM user WHERE email =%s"
        cursor.execute(sql, useremail)
        account = cursor.fetchone()
        if account:
            return render_template('signup.html', msg="You are already a member, please login using your details")
        else:
            session['regmail'] = useremail
            otp = randint(000000, 999999)
            msg = Message(subject='OTP', sender='hackjacks@gmail.com',
                          recipients=[session['regmail']])
            msg.body = ("You have successfully registered for Hire Me!\nUse the OTP given below to verify your email "
                        "ID.\n\t\t") + \
                       str(otp)
            mail.send(msg)
            return render_template('verification.html')

    elif ("regmail" in session):
        if request.method == 'GET':
            otp = randint(000000, 999999)
            msg = Message(subject='OTP', sender='hackjacks@gmail.com',
                          recipients=[session['regmail']])
            msg.body = "You have succesfully registered for Hire Me!\nUse the OTP given below to verify your email ID.\n\t\t" + \
                       str(otp)
            mail.send(msg)
            return render_template('verification.html', resendmsg="OTP has been resent")
    else:
        return redirect('/')


@app.route('/validate', methods=['POST', 'GET'])
def validate():
    if ('regmail' in session):
        global first_name
        global last_name
        global password
        user_otp = request.form['otp']
        if otp == int(user_otp):
            insert_sql = "INSERT INTO user(first_name,last_name,email,pass) values (%s,%s,%s,%s);"
            values = (first_name, last_name, session['regmail'], password)
            cursor.execute(insert_sql, values)
            conn.commit()
            return render_template('signin.html')
        else:
            return render_template('verification.html', msg="OTP is invalid. Please enter a valid OTP")
    else:
        return redirect('/')


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
        audience=GOOGLE_CLIENT_ID,
        clock_skew_in_seconds=5
    )

    session["useremail"] = id_info.get("email")
    session["first_name"] = id_info.get("given_name")
    session["last_name"] = id_info.get("family_name")

    global first_name
    global last_name
    global useremail
    global password

    first_name = session['first_name']
    last_name = session['last_name']
    useremail = session['useremail']
    session['skill'] = 'java'
    password = ""

    sql = "SELECT * FROM user WHERE email =%s;"
    cursor.execute(sql, useremail)
    useraccount = cursor.fetchone()

    if useraccount:
        session['userid'] = useraccount['user_id']
        session['newuser'] = useraccount['newuser']
        if (session['newuser'] == 1):
            return redirect('/profile')
        sql = "SELECT * FROM profile WHERE email_id =%s;"
        cursor.execute(sql, useremail)
        proaccount = cursor.fetchone()
        session['skill'] = proaccount['job_title']
        return redirect('/home')

    else:
        insert_sql = "INSERT INTO user(first_name,last_name,email,pass) VALUES (%s,%s,%s,%s);"
        values = (first_name, last_name, useremail, password)
        cursor.execute(insert_sql, values)
        conn.commit()
        sql = "SELECT * FROM user WHERE email =%s;"
        cursor.execute(sql, useremail)
        useraccount = cursor.fetchone()
        session['userid'] = useraccount['user_id']
        session['newuser'] = useraccount['newuser']
        return redirect("/profile")


@app.route("/logout")
def logout():
    session.clear()
    session.pop('useremail', None)
    session.pop('regmail', None)
    session.pop('newuser', None)
    session.pop('skill', None)
    session.pop('userid', None)
    session.pop('mailcompany', None)
    session.pop('appliedjobid', None)
    session.pop('state', None)
    session.pop('jobid', None)
    session.pop('userid', None)
    session.pop('companies', None)
    session.pop('arr', None)
    return redirect("/login")


@app.route("/home", methods=['POST', 'GET'])
def home():
    if "useremail" in session:
        if request.method == 'POST':
            user_search = request.form.get(
                'search').replace(" ", "").casefold()
            arr = []
            sql = ("SELECT job.*,company.name,company.website,company.logo FROM job JOIN company ON job.company_id = "
                   "company.company_id;")
            cursor.execute(sql)
            dictionary = cursor.fetchone()
            while dictionary is not None:
                if dictionary['name'].replace(" ", "").casefold() == user_search or dictionary['role'].replace(
                        " ", "").casefold() == user_search or dictionary['skill_1'].replace(" ",
                                                                                            "").casefold() == user_search or \
                        dictionary["skill_2"].replace(" ", "").casefold() == user_search or dictionary[
                    "skill_3"].replace(" ", "").casefold() == user_search:
                    dict = {
                        'jobid': dictionary['job_id'], 'cname': dictionary['name'], 'role': dictionary['role'],
                        'ex': dictionary['experience'], 'skill_1': dictionary['skill_1'],
                        'skill_2': dictionary['skill_2'], 'skill_3': dictionary['skill_3'],
                        'vacancy': dictionary['vacancy'], 'stream': dictionary['stream'],
                        'job_location': dictionary['job_location'], 'salary': str(dictionary['salary']),
                        'link': dictionary['website'], 'logo': dictionary['logo'],
                        'description': remove_control_characters(dictionary['description']),
                        'count': dictionary['count']
                    }
                    arr.append(dict)
                dictionary = cursor.fetchone()
            sorted_arr = sorted(arr, key=lambda x: x['count'], reverse=True)
            companies = json.dumps(sorted_arr)
            print(companies)

            return render_template("index.html", companies=companies, arr=sorted_arr, liked=0)
        else:
            arr = []
            sql = ("SELECT job.*, company.name, company.website, company.logo "
                   "FROM job "
                   "JOIN company ON job.company_id = company.company_id "
                   "WHERE job.skill_1 = %s OR job.skill_2 = %s OR job.skill_3 = %s;")
            cursor.execute(sql, (session['skill'],
                                 session['skill'], session['skill']))
            dictionary = cursor.fetchone()
            while dictionary is not None:
                dict = {
                    'jobid': dictionary['job_id'], 'cname': dictionary['name'], 'role': dictionary['role'],
                    'ex': dictionary['experience'], 'skill_1': dictionary['skill_1'], 'skill_2': dictionary['skill_2'],
                    'skill_3': dictionary['skill_3'], 'vacancy': dictionary['vacancy'], 'stream': dictionary['stream'],
                    'job_location': dictionary['job_location'], 'salary': str(dictionary['salary']),
                    'link': dictionary['website'], 'logo': dictionary['logo'],
                    'description': remove_control_characters(dictionary['description']), 'count': dictionary['count']}
                arr.append(dict)
                dictionary = cursor.fetchone()
            sorted_arr = sorted(arr, key=lambda x: x['count'], reverse=True)
            companies = json.dumps(sorted_arr)
            session['companies'] = companies
            session['arr'] = sorted_arr
            message = ''
            if (session.get('msg') is not None):
                message = session.get('msg')
                session.pop('msg')
            return render_template("index.html", companies=companies, arr=sorted_arr, message=message, liked=0)
    else:
        return redirect('/login')


@app.route('/liked', methods=['POST'])
def is_liked():
    liked = 0
    session['jobid'] = request.form['jobid']
    check_sql = "SELECT liked FROM likedjob WHERE user_id = %s and job_id = %s;"
    cursor.execute(check_sql, (session['userid'], session['jobid']))
    acc = cursor.fetchone()
    if not acc:
        print('Not liked before')
        liked = 0
    else:
        liked = 1
        print(f"This is liked {liked}")
        print("liked before")
    check_sql2 = "SELECT count FROM job WHERE job_id = %s;"
    cursor.execute(check_sql2, session['jobid'])
    acc = cursor.fetchone()
    count = acc['count']
    print(f"The count is {count}")
    return jsonify({'liked': liked, 'count': count})


@app.route('/like', methods=['POST'])
def store_like():
    liked = 0
    session['jobid'] = request.form['jobid']
    print(f"The jobid is {session['jobid']}")
    check_sql = "SELECT liked FROM likedjob WHERE user_id = %s and job_id = %s;"
    cursor.execute(check_sql, (session['userid'], session['jobid']))
    acc = cursor.fetchone()
    if not acc:
        insert_sql = "INSERT INTO likedjob(USER_ID,JOB_ID) VALUES(%s,%s);"
        cursor.execute(insert_sql, (session['userid'], session['jobid']))
        conn.commit()
        update_sql = "UPDATE job SET count = count+1 WHERE job_id = %s;"
        cursor.execute(update_sql, session['jobid'])
        conn.commit()
        print('updated')
        sql = "SELECT count FROM job where job_id = %s;"
        cursor.execute(sql, session['jobid'])
        count = cursor.fetchone()['count']
        print(f"The count in if here is {count}")
        liked = 1
    else:
        delete_sql = "DELETE FROM likedjob WHERE USER_ID=%s and JOB_ID=%s;"
        cursor.execute(delete_sql, (session['userid'], session['jobid']))
        conn.commit()
        update_sql = "UPDATE job SET count = count-1 WHERE job_id = %s;"
        cursor.execute(update_sql, session['jobid'])
        conn.commit()
        sql = "SELECT count FROM job where job_id = %s;"
        cursor.execute(sql, session['jobid'])
        count = cursor.fetchone()['count']
        print(f"The count in else here is {count}")
        liked = 0
    return jsonify({'liked': liked, 'count': count})


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        useremail = request.form.get('email')
        password = request.form.get('password')
        sql = "SELECT * FROM user WHERE email =%s;"
        cursor.execute(sql, useremail)
        account = cursor.fetchone()

        if account:
            session["useremail"] = useremail
            session["newuser"] = account['newuser']
            session['userid'] = account['user_id']
            session['skill'] = 'java'
            hashedpwd = str(account['pass']).strip('b').replace("'", "").encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), hashedpwd):
                if (session['newuser'] == 1):
                    return redirect('/profile')
                else:
                    sql = "SELECT job_title FROM profile WHERE email_id =%s;"
                    cursor.execute(sql, useremail)
                    account = cursor.fetchone()
                    session['skill'] = account['job_title']
                    return redirect('/home')
            else:
                return render_template('signin.html', msg="Password is invalid")
        else:
            return render_template('signin.html', msg="Email is invalid")
    else:
        if "useremail" in session:
            return redirect('/home')
        else:
            return render_template('signin.html')


@app.route("/profile", methods=["POST", "GET"])
def profile():
    if "useremail" in session:
        if (session['newuser'] == 1 and request.method == 'POST'):
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
            skill = request.form.get('skill')

            insert_sql = "INSERT INTO profile VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);"

            cursor.execute(insert_sql,
                           (session['userid'], first_name, last_name, mobile_no, address_line_1, address_line_2,
                            zipcode,
                            city, session['useremail'], education, country, state, experience, skill))

            insert_sql = "UPDATE user SET newuser = 0 WHERE email=%s;"
            session['newuser'] = 0
            cursor.execute(insert_sql, session['useremail'])
            conn.commit()
            session['skill'] = skill
            return redirect('/home')

        elif (session['newuser'] == 0 and request.method == "GET"):
            sql = "SELECT * FROM profile WHERE email_id =%s;"
            cursor.execute(sql, session['useremail'])
            account = cursor.fetchone()
            first_name = account['first_name']
            last_name = account['last_name']
            mobile_no = account['mobile_number']
            address_line_1 = account['address_line1']
            address_line_2 = account['address_line2']
            zipcode = account['zipcode']
            education = account['education']
            countries = account['country']
            states = account['state']
            city = account['city']
            experience = account['experience']
            skill = account['job_title']
            return render_template('profile.html', email=session['useremail'], newuser=session['newuser'],
                                   first_name=first_name, last_name=last_name, address_line_1=address_line_1,
                                   address_line_2=address_line_2, zipcode=zipcode, education=education,
                                   countries=countries, states=states, experience=experience, skill=skill,
                                   mobile_no=mobile_no, city=city)

        elif (session['newuser'] == 0 and request.method == "POST"):
            mobile_no = request.form.get('mobile_no')
            address_line_1 = request.form.get('address_line_1')
            address_line_2 = request.form.get('address_line_2')
            zipcode = request.form.get('zipcode')
            city = request.form.get('city')
            country = request.form.get('countries')
            state = request.form.get('states')
            experience = request.form.get('experience')
            skill = request.form.get('skill')
            sql = ("UPDATE profile SET mobile_number=%s,address_line1=%s,address_line2=%s,zipcode=%s,city=%s,"
                   "country=%s,state=%s,experience=%s,job_title=%s where email_id =%s;")
            cursor.execute(sql, (mobile_no, address_line_1, address_line_2, zipcode,
                                 city, country, state, experience, skill, session['useremail']))
            conn.commit()
            session['skill'] = skill
            return redirect("/home")
        else:
            return render_template('profile.html', newuser=session['newuser'], email=session['useremail'])
    else:
        return redirect("/login")


@app.route("/forgotpass", methods=["POST", "GET"])
def forgotpass():
    global i
    global otp
    global email

    if request.method == 'POST':
        useremail = request.form.get('email')
        user_otp = request.form.get('OTP')
        password = request.form.get('password')
        print(useremail)
        sql = "SELECT * FROM user WHERE email =%s;"
        cursor.execute(sql, (useremail,))
        account = cursor.fetchone()

        if i == 1:
            if otp == int(user_otp):
                i = 2
                return render_template('forgotpass.html', i=i)
            else:
                return render_template('forgotpass.html', msg="OTP is invalid. Please enter a valid OTP", i=i)

        elif i == 2:
            sql = "UPDATE user SET pass=%s WHERE email=%s;"
            cursor.execute(sql, (password, email))
            conn.commit()
            i = 1
            return render_template('signin.html')

        elif i == 0:
            if (account):
                otp = randint(000000, 999999)
                email = request.form['email']
                msg = Message(subject='OTP', sender='hackjacks@gmail.com',
                              recipients=[email])
                msg.body = "Forgot your password?\n\nWe received a request to reset the password for your account.Use the OTP given below to reset the password.\n\n" + \
                           str(otp)
                mail.send(msg)
                i = 1
                return render_template('forgotpass.html', i=i)
            else:
                return render_template('forgotpass.html', msg="It looks like you are not yet our member!")
    i = 0
    return render_template('forgotpass.html')


@app.route("/apply/<string:jobid>", methods=["POST", "GET"])
def apply(jobid):
    if "useremail" in session:
        if request.method == "POST":
            session['appliedjobid'] = json.loads(jobid)
            sql = "select * from appliedjob where user_id=%s and job_id=%s;"
            cursor.execute(sql, (session['userid'], session['appliedjobid']))
            account = cursor.fetchone()
            if account:
                session['msg'] = "You have already applied for this job!"
                session['error'] = True
                # return render_template("index.html", msg="You have already applied for this job!")
                return redirect("/home")
            # return redirect("/apply")
        elif (jobid == "profile"):
            return redirect('/profile')
        # else:
        jobsql = "SELECT name FROM job JOIN company on job.company_id = company.company_id WHERE job_id = %s"
        cursor.execute(jobsql, jobid)
        appliedcompany = cursor.fetchone()
        session['mailcompany'] = appliedcompany['name']
        sql = "SELECT * FROM profile WHERE email_id =%s"
        cursor.execute(sql, session['useremail'])
        account = cursor.fetchone()
        first_name = account['first_name']
        last_name = account['last_name']
        mobile_no = account['mobile_number']
        zipcode = account['zipcode']
        education = account['education']
        countries = account['country']
        states = account['state']
        city = account['city']
        experience = account['experience']
        return render_template('apply.html', email=session['useremail'], first_name=first_name, last_name=last_name,
                               zipcode=zipcode, education=education, countries=countries, states=states,
                               experience=experience, mobile_no=mobile_no, city=city)
    else:
        return redirect('/login')


@app.route("/applysuccess", methods=["POST", 'GET'])
def applysuccess():
    if "useremail" in session:
        if request.method == "POST":
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            mobile_no = request.form.get('mobile_no')
            zipcode = request.form.get('zipcode')
            city = request.form.get('city')
            education = request.form.get('education')
            country = request.form.get('countries')
            state = request.form.get('states')
            experience = request.form.get('experience')
            insert_sql = ("INSERT INTO appliedjob(user_id,job_id,first_name,last_name,mobile_number,zipcode,city,"
                          "email,education,country,state,experience) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)")
            cursor.execute(insert_sql, (session['userid'], session['appliedjobid'], first_name, last_name,
                                        mobile_no, zipcode, city, session['useremail'], education, country, state,
                                        experience))
            conn.commit()
            msg = Message(subject='Job Application Notification', sender='hackjacks@gmail.com',
                          recipients=[session['useremail']])
            msg.body = "You have applied for the job posted by " + \
                       session['mailcompany'] + "\nBest of Luck!!!"
            mail.send(msg)
            return redirect('/applysuccess')
        else:
            return render_template('applysuccess.html'), {"Refresh": "5; url=/home"}

    else:
        return redirect('/home')


@app.route("/adminlogin", methods=['GET', 'POST'])
def adminlogin():
    if request.method == 'POST':
        adminmail = request.form.get('email')
        password = request.form.get('password')
        sql = "SELECT * FROM admin WHERE email =%s"
        cursor.execute(sql, adminmail)
        account = cursor.fetchone()
        if account:
            session["adminmail"] = adminmail
            if (password == str(account['password']).strip()):
                return render_template('adminhome.html')
            else:
                return render_template('adminlogin.html', msg="Password is invalid")
        else:
            return render_template('adminlogin.html', msg="Email is invalid")
    else:
        return render_template('adminlogin.html')


@app.route("/adminhome", methods=['GET', 'POST'])
def adminhome():
    if "adminmail" in session:
        if request.method == 'POST':
            company_name = request.form.get('company_name')
            role = request.form.get('role')
            skill_1 = request.form.get('skill_1')
            skill_2 = request.form.get('skill_2')
            skill_3 = request.form.get('skill_3')
            vacancy = request.form.get('vacancy')
            stream = request.form.get('stream')
            job_location = request.form.get('job_location')
            salary = request.form.get('salary')
            experience = request.form.get('experience')
            link = request.form.get('link')
            logo = request.form.get('logo')
            description = request.form.get('description')

            company_check_sql = "SELECT company_id from company where name = %s;"
            cursor.execute(company_check_sql, company_name.strip().replace(" ", "").casefold())
            company_list = cursor.fetchone()

            if company_list:
                company_id = company_list['company_id']
            else:
                company_insert_sql = "INSERT INTO company(name,website,logo) VALUES(%s, %s, %s)"
                cursor.execute(company_insert_sql, (company_name, link, logo))
                conn.commit()
                cursor.execute("SELECT LAST_INSERT_ID() AS company_id;")
                company_id = cursor.fetchone()['company_id']

            job_insert_sql = ("INSERT INTO job(company_id, role, experience, skill_1, skill_2, skill_3, vacancy, "
                              "stream, job_location, salary, description) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);")
            cursor.execute(job_insert_sql, (company_id, role, experience, skill_1, skill_2,
                                            skill_3, vacancy, stream, job_location, salary, description))
            conn.commit()

            sql = 'SELECT email_id from profile Where job_title = %s or job_title = %s or job_title = %s;'
            cursor.execute(sql, (skill_1, skill_2, skill_3))
            account = cursor.fetchone()
            while account is not None:
                msg = Message(subject='Job Posting', sender='hackjacks@gmail.com',
                              recipients=[account['email_id']])

                msg.body = company_name + (" has posted a new job. We are sending you this mail since you have a skill "
                                           "matching a job "
                                           "posted by " + company_name)
                mail.send(msg)
                account = cursor.fetchone()
            return render_template('adminhome.html')

        return render_template('adminhome.html')
    else:
        return redirect('/adminlogin')


@app.route("/adminlogout")
def adminlogout():
    session.pop('adminmail', None)
    return redirect("/adminlogin")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
