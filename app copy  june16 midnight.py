import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response



# FUNCTIONS login(), logout(), register(), index(), QUOTE(), BUY(), SELL(), HISTORY()



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("You must provide a username!")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("You must provide password!")

        # Query database for username
        users = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(users) != 1 or not check_password_hash(
            users[0]["hash"], request.form.get("password")
        ):
            return apology("That is an invalid username and/or password!")

        # Remember which user has logged in
        session["user_id"] = users[0]["user_id"]

        # Redirect user to home page
        user = users[0]['username']
        #cash = usd(users[0]['cash'])
        #flashmessage = "Welcome " + user + "! Your cash balance : " + cash
        flashmessage = "Welcome back " + user + "! "
        flash( flashmessage )
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("login.html")



@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    flash('You are logged out')
    return render_template("login.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        password2 = request.form.get("password2")

        # Ensure username was submitted
        if not username:
            return apology("You must provide username!")

        # Query database for same username
        checkuser = db.execute("SELECT * FROM users WHERE username = ?", username)
        if checkuser:
            return apology("That user already exists!")

        # Ensure password was submitted
        elif not password:
            return apology("You must provide password!")

        # Ensure 2nd password was submitted
        elif not password2:
            return apology("You must verify the password!")

        # Ensure password and 2nd password match
        elif password != password2:
            return apology("The passwords do not match!")

        hashedpw = generate_password_hash(password, method='pbkdf2', salt_length=16)

        # Attempt to insert new user into database, display error if there is a problem
        try:
            db.execute("INSERT INTO users (username, hash, cash) VALUES(?, ?, ?)", username, hashedpw, 10000)
            flash('Registered!')
            return render_template("login.html")
        except ValueError:
            alertmessage=True
            return apology("Retry, there was an unforeseen problem!")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("register.html")



@app.route("/")
@login_required
def index():
    user_id= session["user_id"]
    users = db.execute("SELECT * FROM users WHERE user_id = ?", user_id)
    cash = users[0]['cash']

    """Show portfolio of stocks"""
    holdings = db.execute("SELECT * FROM holdings WHERE user_id = ?", user_id)
    return render_template("index.html", holdings=holdings, cash=cash, lookup=lookup)



# MAIN FUNCTIONS : QUOTE, BUY, SELL, HISTORY



@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get('symbol')
        if not lookup(symbol):
            flash('That symbol does not exist')
            return render_template("quote.html")
        lookupsymbol = lookup(symbol)['symbol']
        lookupprice = lookup(symbol)['price']
        quotemessage = 'The price of ' + lookupsymbol + ' is $' + str(lookupprice) + ' US per share'
        flash(quotemessage)
        return render_template("quote.html")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("quote.html")



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    user_id= session["user_id"]
    users = db.execute("SELECT * FROM users WHERE user_id = ?", user_id)
    cash = users[0]['cash']

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if request.form.get('symbol') and request.form.get('quantity'):
            if not request.form.get('quantity').isdigit():
                return apology("Only whole stocks can be bought!")
            else:
                buystock = request.form.get('symbol').upper().strip()
                if not lookup(buystock):
                    return apology('That stock symbol does not exist!')
        else:
            return apology("You must enter a symbol and quantity to buy!")

        price = lookup(buystock)['price']
        buyquantity = int(request.form.get('quantity'))

        if (price * buyquantity) > cash:
            return apology("You don't have enough cash to buy that quantity!")

        #it's a purchase!
        #update cash
        cash = cash - price * buyquantity
        db.execute("UPDATE users SET cash = ? WHERE user_id = ?;", cash, user_id)

        havequantity = db.execute("SELECT quantity FROM holdings WHERE user_id = ? AND stock = ?;", user_id, buystock)
        if havequantity:
            #update holdings
            newquantity = int(havequantity[0]['quantity']) + buyquantity
            db.execute("UPDATE holdings SET quantity = ? WHERE user_id = ? AND stock = ?;", newquantity, user_id, buystock)
        else:
            db.execute("INSERT INTO holdings (user_id, stock, quantity) VALUES (?,?,?);", user_id, buystock, buyquantity)

        #update transactions
        now = datetime.now()
        transactiondate = now.strftime("%Y-%m-%d %H:%M:%S")
        db.execute("INSERT INTO transactions (user_id, stock, price, quantity, date) VALUES (?,?,?,?,?);", user_id, buystock, price, buyquantity, transactiondate)

        #flash message to confirm
        saleconfirmed='Bought ' + str(buyquantity) + ' share of ' + buystock + ' for ' + usd(price * buyquantity)
        flash(saleconfirmed)
        return redirect("/buy")

    # User reached route via GET (as by clicking a link or via redirect)
    """Show portfolio of stocks"""
    holdings = db.execute("SELECT * FROM holdings WHERE user_id = ?", user_id)
    return render_template("buy.html", holdings=holdings, cash=cash, lookup=lookup)



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():

    """Sell shares of stock"""
    user_id= session["user_id"]
    users = db.execute("SELECT * FROM users WHERE user_id = ?", user_id)
    #        user = users[0]['username']
    cash = users[0]['cash']

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if request.form.get('symbol') and request.form.get('quantity'):
            if not request.form.get('quantity').isdigit():
                return apology("Only whole stocks can be sold!")
            else:
                sellstock = request.form.get('symbol').upper().strip()
                sellquantity = int(request.form.get('quantity'))
        else:
            return apology("You must enter a symbol and quantity to sell!")

        havestock = db.execute("SELECT quantity FROM holdings WHERE user_id = ? AND stock = ?;", user_id, sellstock)
        if not havestock:
            return apology("You don't have that stock to sell!")
        else:
            holdingquantity = int(havestock[0]['quantity'])
            price = lookup(sellstock)['price']

            if holdingquantity < sellquantity:
                return apology("You don't have that much of that stock to sell!")
            else:
                #it's a sale!

                #update cash
                cash = cash + price * sellquantity
                db.execute("UPDATE users SET cash = ? WHERE user_id = ?;", cash, user_id)

                #update holdings
                holdingquantity = holdingquantity - sellquantity
                db.execute("UPDATE holdings SET quantity = ? WHERE user_id = ? AND stock = ?;", holdingquantity, user_id, sellstock)
                #remove strocks with a zero quantity
                db.execute("DELETE FROM holdings WHERE quantity =0;")

                #update transactions
                now = datetime.now()
                transactiondate = now.strftime("%Y-%m-%d %H:%M:%S")
                db.execute("INSERT INTO transactions (user_id, stock, price, quantity, date) VALUES (?,?,?,?,?);", user_id, sellstock, price, -sellquantity, transactiondate)

                #flash message to confirm
                saleconfirmed='Sold ' + str(sellquantity) + ' share of ' + sellstock + ' for ' + usd(price * sellquantity)
                flash(saleconfirmed)
                return redirect("/sell")

    # User reached route via GET (as by clicking a link or via redirect)
    """Show portfolio of stocks"""
    holdings = db.execute("SELECT * FROM holdings WHERE user_id = ?", user_id)
    return render_template("sell.html", holdings=holdings, cash=cash, lookup=lookup)



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id= session["user_id"]
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", user_id)
    return render_template("history.html", transactions=transactions)
