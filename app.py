from flask import Flask,render_template,request,redirect,url_for,session
import pymysql
from werkzeug.security import generate_password_hash,check_password_hash

app=Flask(__name__)
app.secret_key="secret"

app.config['MYSQL_HOST']='localhost'
app.config['MYSQL_USER']='root'
app.config['MYSQL_PASSWORD']='abcd6658'
app.config['MYSQL_DB']='shiftscheduling'

def db_conn():
    return pymysql.connect(host=app.config['MYSQL_HOST'],user=app.config['MYSQL_USER'],password=app.config['MYSQL_PASSWORD'],database=app.config['MYSQL_DB'],cursorclass=pymysql.cursors.DictCursor)

@app.route("/")
def landing():
    return render_template("landing.html")

# ---------- ORG AUTH ----------

@app.route("/signup",methods=["GET","POST"])
def signup():
    if request.method=="POST":
        name,email=request.form["name"],request.form["email"]
        pw=generate_password_hash(request.form["password"])
        db=db_conn();cur=db.cursor()
        cur.execute("INSERT INTO organizations (name,email,password_hash) VALUES (%s,%s,%s)",(name,email,pw))
        db.commit()
        session["oid"]=cur.lastrowid
        return redirect("/dashboard")
    return render_template("signup.html")

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=request.form["email"]
        pw=request.form["password"]
        db=db_conn();cur=db.cursor()
        cur.execute("SELECT * FROM organizations WHERE email=%s",(email,))
        org=cur.fetchone()
        if org and check_password_hash(org["password_hash"],pw):
            session["oid"]=org["oid"]
            return redirect("/dashboard")
    return render_template("login.html")

# ---------- USER LOGIN ----------

@app.route("/user_login",methods=["GET","POST"])
def user_login():
    if request.method=="POST":
        email=request.form["email"]
        pw=request.form["password"]
        db=db_conn();cur=db.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s",(email,))
        user=cur.fetchone()

        if user and check_password_hash(user["password_hash"],pw):
            session["uid"]=user["uid"]
            return redirect("/user_dashboard")

    return render_template("user_login.html")

@app.route("/user_dashboard")
def user_dash():

    if "uid" not in session:
        return redirect("/user_login")

    db=db_conn();cur=db.cursor()

    cur.execute("""
    SELECT u.name,u.email,d.name department
    FROM users u
    LEFT JOIN departments d ON u.did=d.did
    WHERE u.uid=%s
    """,(session["uid"],))

    user=cur.fetchone()

    return render_template("user_dashboard.html",user=user)

# ---------- ORG DASH ----------

@app.route("/dashboard")
def dashboard():

    if "oid" not in session:
        return redirect("/login")

    db=db_conn();cur=db.cursor()

    cur.execute("""
    SELECT u.uid,u.name,u.email,d.name department
    FROM users u
    LEFT JOIN departments d ON u.did=d.did
    WHERE u.oid=%s
    """,(session["oid"],))

    users=cur.fetchall()

    cur.execute("SELECT * FROM departments WHERE oid=%s",(session["oid"],))
    depts=cur.fetchall()

    return render_template("dashboard.html",users=users,depts=depts)

# ---------- ADD USER ----------

@app.route("/add_user",methods=["POST"])
def add_user():

    name,email,did=request.form["name"],request.form["email"],request.form["did"]

    default_pw=generate_password_hash("1234")

    db=db_conn();cur=db.cursor()

    cur.execute("""
    INSERT INTO users (oid,did,name,email,password_hash)
    VALUES (%s,%s,%s,%s,%s)
    """,(session["oid"],did,name,email,default_pw))

    db.commit()

    return redirect("/dashboard")

# ---------- DELETE USER ----------

@app.route("/delete_user/<uid>")
def delete_user(uid):

    db=db_conn();cur=db.cursor()

    cur.execute("DELETE FROM users WHERE uid=%s AND oid=%s",(uid,session["oid"]))

    db.commit()

    return redirect("/dashboard")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

app.run(debug=True)