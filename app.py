import sqlite3
from flask import Flask, g, session, render_template, request, redirect
from datetime import timedelta
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
# for session
app.secret_key = 'test'
app.permanent_session_lifetime = timedelta(minutes=5)

DATABASE = 'pointcard.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)

    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route("/")
def index():
    print("return")
    if "id" in session:
        status = "login"
    else:
        status = "unknown"

    return render_template(
        "index.html",
        status = status
    )




@app.route("/logout")
def logout():
    """Log user out"""
    # Forget session
    session.clear()
    # Redirect user to login form
    return redirect("login")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any session
    session.clear()
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)
        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        # Query database for username
        cursor = get_db().cursor()
        rows = cursor.execute("SELECT * FROM users WHERE username = ?", [request.form.get("username")])
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hashedpassword"], [request.form.get("password")]):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["id"] = rows[0]["id"]
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any session
    session.clear()
    print("pre")
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        print("post")
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirmation (= password) was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)

        # Ensure password = confirmmation was same
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("must provide the same password for the confirmation", 400)

        # Query database for username
        cursor = get_db().cursor()
        rows = cursor.execute("SELECT * FROM users WHERE username = ?", [request.form.get("username")])

        print("DATABASE:",len(rows.fetchall()))
        # Ensure username is not exist
        if len(rows.fetchall()) != 0:
            return apology("username already exists", 400)
        else:
            username = request.form.get("username")
            hashedPassword = generate_password_hash(request.form.get("password"),method='pbkdf2:sha256', salt_length=8)
            connection=get_db()
            cursor = connection.cursor()
            cursor.execute("INSERT INTO users (username, hashedpassword) VALUES (?, ?)", [username, hashedPassword])
            userid = cursor.execute("SELECT id FROM users WHERE username = ?", [request.form.get("username")])
            session["id"] = int(userid.fetchall()[0][0])
            connection.commit()
            # Remember which user has logged in
        # Redirect user to home page
        return redirect("/")


    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":
        return render_template("register.html")


def apology(message, code):
    return render_template("apology.html", code=code, message = message)
