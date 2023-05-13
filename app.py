import json
import unicodedata
import os
import pyodbc
import pathlib
from random import randint

import flask
import google.auth.transport.requests
import requests
from flask import Flask, abort, redirect, render_template, request, session, jsonify
from flask_mail import Mail, Message
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol


azureserver = 'sqlhireme.database.windows.net'
azuredatabase = 'sqldb'
azureusername = 'a6hi27'
azurepassword = '*Abhinav123'
azuredriver = '{ODBC Driver 17 for SQL Server}'
conn = pyodbc.connect('DRIVER='+azuredriver+';SERVER=tcp:'+azureserver +
                      ';PORT=1433;DATABASE='+azuredatabase+';UID='+azureusername+';PWD='+azurepassword)
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
app.config['MAIL_PASSWORD'] = 'oimptgpdjiukindy'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


GOOGLE_CLIENT_ID = "423186228081-7pf3urrp4hfk1ksjdb9ev9t7dbj1iden.apps.googleusercontent.com"
client_secrets_file = os.path.join(
    pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri = "http://localhost:5000/callback"
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
        password = request.form.get('password')
        useremail = request.form.get('email')
        sql = "SELECT * FROM users WHERE email =?"
        cursor.execute(sql, useremail)
        account = cursor.fetchone()
        if (account):
            return render_template('signup.html', msg="You are already a member, please login using your details")
        else:
            session['regmail'] = useremail
            otp = randint(000000, 999999)
            msg = Message(subject='OTP', sender='hackjacks@gmail.com',
                          recipients=[session['regmail']])
            msg.body = "You have succesfully registered for Hire Me!\nUse the OTP given below to verify your email ID.\n\t\t" + \
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
            insert_sql = "INSERT INTO users(first_name,last_name,email,pass) values (?,?,?,?)"
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
    password = ""

    sql = "SELECT * FROM users WHERE email =?"
    cursor.execute(sql, useremail)
    useraccount = cursor.fetchone()

    if useraccount:
        session['userid'] = useraccount[0]
        session['newuser'] = useraccount[5]
        if (session['newuser'] == 1):
            return redirect('/profile')
        sql = "SELECT * FROM profile WHERE email_id =?"
        cursor.execute(sql, useremail)
        proaccount = cursor.fetchone()
        session['skill'] = proaccount[12]
        return redirect('/home')

    else:
        insert_sql = "INSERT INTO users(first_name,last_name,email,pass) VALUES (?,?,?,?)"
        values = (first_name, last_name, useremail, password)
        cursor.execute(insert_sql, values)
        conn.commit()
        sql = "SELECT * FROM users WHERE email =?"
        cursor.execute(sql, useremail)
        useraccount = cursor.fetchone()
        session['userid'] = useraccount[0]
        session['newuser'] = useraccount[5]
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
            sql = "SELECT * FROM companies"
            cursor.execute(sql)
            dictionary = cursor.fetchone()
            while dictionary is not None:
                if dictionary[1].replace(" ", "").casefold() == user_search or dictionary[2].replace(" ", "").casefold() == user_search or dictionary[4].replace(" ", "").casefold() == user_search or dictionary[5].replace(" ", "").casefold() == user_search or dictionary[6].replace(" ", "").casefold() == user_search:
                    dict = {
                        'jobid': dictionary[0], 'cname': dictionary[1], 'role': dictionary[2], 'ex': dictionary[3], 'skill_1': dictionary[4], 'skill_2': dictionary[5], 'skill_3': dictionary[6], 'vacancy': dictionary[7], 'stream': dictionary[8], 'job_location': dictionary[9], 'salary': str(dictionary[10]), 'link': dictionary[11], 'logo': dictionary[12], 'description': remove_control_characters(dictionary[13]), 'count': dictionary[14]
                    }
                    arr.append(dict)
                dictionary = cursor.fetchone()
            sorted_arr = sorted(arr, key=lambda x: x['count'], reverse=True)
            companies = json.dumps(sorted_arr)

            return render_template("index.html", companies=companies, arr=sorted_arr, liked=0)
        else:
            arr = []
            sql = "SELECT * FROM companies where skill_1 = ? or skill_2 = ? or skill_3 = ?"
            cursor.execute(sql, session['skill'],
                           session['skill'], session['skill'])
            dictionary = cursor.fetchone()
            while dictionary is not None:
                dict = {
                    'jobid': dictionary[0], 'cname': dictionary[1], 'role': dictionary[2], 'ex': dictionary[3], 'skill_1': dictionary[4], 'skill_2': dictionary[5], 'skill_3': dictionary[6], 'vacancy': dictionary[7], 'stream': dictionary[8], 'job_location': dictionary[9], 'salary': str(dictionary[10]), 'link': dictionary[11], 'logo': dictionary[12], 'description': remove_control_characters(dictionary[13]), 'count': dictionary[14]
                }
                arr.append(dict)
                dictionary = cursor.fetchone()
            # arr.reverse()
            sorted_arr = sorted(arr, key=lambda x: x['count'], reverse=True)
            companies = json.dumps(sorted_arr)
            session['companies'] = companies
            session['arr'] = sorted_arr
            # msg = getattr(session, 'msg', "")
            # print(session)
            # print("msg = ", msg)
            # if(getattr(session, 'msg', None) is not None):
            #     session.pop('msg')
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
    check_sql = "SELECT * FROM LIKES WHERE userid = ? and job_id = ?;"
    cursor.execute(check_sql, session['userid'], session['jobid'])
    acc = cursor.fetchone()
    if not acc:
        print('Not liked before')
        liked = 0
    else:
        liked = 1
        print(f"This is liked {liked}")
        print("liked before")
    check_sql2 = "SELECT count FROM companies WHERE job_id = ?;"
    cursor.execute(check_sql2, session['jobid'])
    acc = cursor.fetchone()
    count = acc[0]
    print(f"The count is {count}")
    return jsonify({'liked': liked, 'count': count})


@app.route('/like', methods=['POST'])
def store_like():
    liked = 0
    session['jobid'] = request.form['jobid']
    print(f"The jobid is {session['jobid']}")
    check_sql = "SELECT * FROM LIKES WHERE userid = ? and job_id = ?;"
    cursor.execute(check_sql, session['userid'], session['jobid'])
    acc = cursor.fetchone()
    if not acc:
        insert_sql = "INSERT INTO LIKES(USERID,JOB_ID) VALUES(?,?);"
        cursor.execute(insert_sql, session['userid'], session['jobid'])
        conn.commit()
        update_sql = "UPDATE companies SET count = count+1 WHERE job_id = ?;"
        cursor.execute(update_sql, session['jobid'])
        conn.commit()
        print('updated')
        sql = "SELECT count FROM companies where job_id = ?;"
        cursor.execute(sql, session['jobid'])
        count = cursor.fetchone()[0]
        print(f"The count in if here is {count}")
        # dictionary = cursor.fetchone()
        # while dictionary is not None:
        #     dict = {
        #         'jobid': dictionary[0], 'cname': dictionary[1], 'role': dictionary[2], 'ex': dictionary[3], 'skill_1': dictionary[4], 'skill_2': dictionary[5], 'skill_3': dictionary[6], 'vacancy': dictionary[7], 'stream': dictionary[8], 'job_location': dictionary[9], 'salary': str(dictionary[10]), 'link': dictionary[11], 'logo': dictionary[12], 'description': remove_control_characters(dictionary[13]), 'count': dictionary[14]
        #     }
        #     arr.append(dict)
        #     dictionary = cursor.fetchone()
        #     # arr.reverse()
        # sorted_arr = sorted(arr, key=lambda x: x['count'], reverse=True)
        # companies = json.dumps(sorted_arr)
        # session['companies'] = companies
        # session['arr'] = sorted_arr
        liked = 1
    else:
        delete_sql = "DELETE FROM LIKES WHERE USERID=? and JOB_ID=?;"
        cursor.execute(delete_sql, session['userid'], session['jobid'])
        conn.commit()
        update_sql = "UPDATE companies SET count = count-1 WHERE job_id = ?;"
        cursor.execute(update_sql, session['jobid'])
        conn.commit()
        sql = "SELECT count FROM companies where job_id = ?;"
        cursor.execute(sql, session['jobid'])
        count = cursor.fetchone()[0]
        print(f"The count in else here is {count}")
        # dictionary = cursor.fetchone()
        # while dictionary is not None:
        #     dict = {
        #         'jobid': dictionary[0], 'cname': dictionary[1], 'role': dictionary[2], 'ex': dictionary[3], 'skill_1': dictionary[4], 'skill_2': dictionary[5], 'skill_3': dictionary[6], 'vacancy': dictionary[7], 'stream': dictionary[8], 'job_location': dictionary[9], 'salary': str(dictionary[10]), 'link': dictionary[11], 'logo': dictionary[12], 'description': remove_control_characters(dictionary[13]), 'count': dictionary[14]
        #     }
        #     arr.append(dict)
        #     dictionary = cursor.fetchone()
        #     # arr.reverse()
        # sorted_arr = sorted(arr, key=lambda x: x['count'], reverse=True)
        # companies = json.dumps(sorted_arr)
        # session['companies'] = companies
        # session['arr'] = sorted_arr
        liked = 0
    return jsonify({'liked': liked, 'count': count})
    # return render_template('index.html', companies=session['companies'], arr=session['arr'],liked=liked)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        useremail = request.form.get('email')
        password = request.form.get('password')
        sql = "SELECT * FROM users WHERE email =?;"
        cursor.execute(sql, useremail)
        account = cursor.fetchone()

        if account:
            session["useremail"] = useremail
            session["newuser"] = account[5]
            session['userid'] = account[0]

            if (password == str(account[4]).strip()):
                if (session['newuser'] == 1):
                    return redirect('/profile')
                else:
                    sql = "SELECT * FROM profile WHERE email_id =?;"
                    cursor.execute(sql, useremail)
                    account = cursor.fetchone()
                    session['skill'] = account[12]
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

            insert_sql = "INSERT INTO profile VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"

            cursor.execute(insert_sql, first_name, last_name, mobile_no, address_line_1, address_line_2,
                           zipcode, city, session['useremail'], education, country, state, experience, skill, session['userid'])

            insert_sql = "UPDATE users SET newuser = 0 WHERE email=?"
            session['newuser'] = 0
            cursor.execute(insert_sql, session['useremail'])
            conn.commit()
            session['skill'] = skill
            return redirect('/home')

        elif (session['newuser'] == 0 and request.method == "GET"):
            sql = "SELECT * FROM profile WHERE email_id =?"
            cursor.execute(sql, session['useremail'])
            account = cursor.fetchone()
            first_name = account[0]
            last_name = account[1]
            mobile_no = account[2]
            address_line_1 = account[3]
            address_line_2 = account[4]
            zipcode = account[5]
            education = account[8]
            countries = account[9]
            states = account[10]
            city = account[6]
            experience = account[11]
            skill = account[12]
            return render_template('profile.html', email=session['useremail'], newuser=session['newuser'], first_name=first_name, last_name=last_name, address_line_1=address_line_1, address_line_2=address_line_2, zipcode=zipcode, education=education, countries=countries, states=states, experience=experience, skill=skill, mobile_no=mobile_no, city=city)

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
            sql = "UPDATE profile SET mobile_number=?,address_line1=?,address_line2=?,zipcode=?,city=?,country=?,state=?,experience=?,skill=? where email_id =?"
            cursor.execute(sql, mobile_no, address_line_1, address_line_2, zipcode,
                           city, country, state, experience, skill, session['useremail'])
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

        sql = "SELECT * FROM users WHERE email =?"
        cursor.execute(sql, useremail)
        account = cursor.fetchone()

        if i == 1:
            if otp == int(user_otp):
                i = 2
                return render_template('forgotpass.html', i=i)
            else:
                return render_template('forgotpass.html', msg="OTP is invalid. Please enter a valid OTP", i=i)

        elif i == 2:
            sql = "UPDATE users SET pass=? WHERE email=?"
            cursor.execute(sql, password, email)
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
            sql = "select * from appliedcompany where userid=?"
            cursor.execute(sql, session['userid'])
            account = cursor.fetchone()
            while (account is not None):
                if (session['appliedjobid'] == account[1]):
                    session['msg'] = "You have already applied for this job!"
                    session['error'] = True
                    # return render_template("index.html", msg="You have already applied for this job!")
                    return redirect("/home")
                account = cursor.fetchone()

            # return redirect("/apply")
        elif (jobid == "profile"):
            return redirect('/profile')
        # else:
        jobsql = "SELECT * FROM companies WHERE job_id =?"
        cursor.execute(jobsql, jobid)
        appliedcompany = cursor.fetchone()
        session['mailcompany'] = appliedcompany[1]
        sql = "SELECT * FROM profile WHERE email_id =?"
        cursor.execute(sql, session['useremail'])
        account = cursor.fetchone()
        first_name = account[0]
        last_name = account[1]
        mobile_no = account[2]
        zipcode = account[5]
        education = account[8]
        countries = account[9]
        states = account[10]
        city = account[6]
        experience = account[11]
        return render_template('apply.html', email=session['useremail'], first_name=first_name, last_name=last_name, zipcode=zipcode, education=education, countries=countries, states=states, experience=experience, mobile_no=mobile_no, city=city)
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
            insert_sql = "INSERT INTO appliedcompany(userid,jobid,first_name,last_name,mobile_number,zipcode,city,email,education,country,state,experience) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
            cursor.execute(insert_sql, session['userid'], session['appliedjobid'], first_name, last_name,
                           mobile_no, zipcode, city, session['useremail'], education, country, state, experience)
            conn.commit()
            msg = Message(subject='Job Application Notification', sender='hackjacks@gmail.com',
                          recipients=[session['useremail']])
            msg.body = "You have applied for the job posted by " + \
                session['mailcompany']+"\nBest of Luck!!!"
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
        sql = "SELECT * FROM admin WHERE email =?"
        cursor.execute(sql, adminmail)
        account = cursor.fetchone()
        if account:
            session["adminmail"] = adminmail
            if (password == str(account[1]).strip()):
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

            insert_sql = "INSERT INTO companies (company_name, role, experience, skill_1, skill_2, skill_3, vacancy, stream, job_location, salary, website, logo,description) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"

            cursor.execute(insert_sql, company_name, role, experience, skill_1, skill_2,
                           skill_3, vacancy, stream, job_location, salary, link, logo, description)
            conn.commit()

            sql = 'SELECT email_id from profile Where skill = ? or skill = ? or skill = ?'
            cursor.execute(sql, skill_1, skill_2, skill_3)
            account = cursor.fetchone()
            while account is not None:
                msg = Message(subject='Job Posting', sender='hackjacks@gmail.com',
                              recipients=[account[0]])

                msg.body = company_name+"has posted a new job. We are sending you this mail since you chose one of this company's required skill as your preferred skill"
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
