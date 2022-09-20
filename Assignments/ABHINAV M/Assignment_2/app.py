from flask import Flask
from flask import render_template

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/signup")
def signup():
    return render_template("signup.html")


@app.route("/signin")
def signin():
    return render_template("signin.html")

@app.route("/aboutus")
def aboutus():
    return render_template("aboutus.html")
