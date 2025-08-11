# Import all the needed modules for the application.
import base64, hashlib, os, sqlite3
from datetime import timedelta
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from support import login_required, valid_password
from api import todo_bp, get_db, init_app

# Configure the application and use a secure secret key.
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "super-secret-dev-key")
app.config["UPLOAD_FOLDER"] = "static/uploads"
# 2MB max file size.
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  

# Register the Blueprint.
app.register_blueprint(todo_bp)
# Register teardown handler.
init_app(app)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

# Allow file extension check.
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS 

# Configure the application to have user logged in until requested to logout (up to 10 years).
app.permanent_session_lifetime = timedelta(days= 365 * 0.1)

@app.before_request
def make_session_permanent():
    session.permanent = True

# Home route that user sees once logged in.
@app.route("/")
@login_required
def index():
    """Show homepage of SketchList with user's todos."""
    db = get_db()
    todos = db.execute(
        "SELECT * FROM todo WHERE user_id = ? ORDER BY updated DESC", 
        (session["user_id"],)
    ).fetchall()

    # Convert binary drawings to base64 data URLs
    todo_list = []
    for todo in todos:
        drawing_blob = todo["drawing"]
        if drawing_blob:
            base64_drawing = base64.b64encode(drawing_blob).decode("utf-8")
            drawing_url = f"data:image/png;base64,{base64_drawing}"
        else:
            drawing_url = None

        todo_dict = dict(todo)
        todo_dict["drawing_url"] = drawing_url
        todo_list.append(todo_dict)

    return render_template("index.html", todos=todo_list)

# Add todo route that helps users add new tasks.
@app.route("/add_todo", methods=["GET", "POST"])
@login_required
def add_todo():
    """ Let user add more tasks todo"""
    # Set up needed variable and ensure that a title is added when form is posted.
    if request.method == "POST":
        drawing = request.form.get("drawing_data")
        description = request.form.get("description")
        title = request.form.get("title")

        # Handle edge case: drawing might come in as a list
        if isinstance(drawing, list):
            drawing = drawing[0]

        # Title should be required from user.
        if not title:
            flash("Please provide a title for todo.")
            return redirect(url_for("add_todo"))
        
        if drawing:
            header, encoded = drawing.split(",", 1)
            # Decode the image into binary
            drawing_blob = base64.b64decode(encoded)
        else:
            drawing_blob = None
        
        # Add the new data into the database.
        db = get_db()
        db.execute("""INSERT INTO todo (user_id, title, description, drawing)
                   VALUES (?, ?, ?, ?)""",
                   (session["user_id"], title, description, drawing_blob))
        db.commit()
        return redirect(url_for("index"))

    return render_template("add_todo.html")

# Allow user to delete a todo item if user pleases.
@app.route("/delete/<int:todo_id>")
@login_required
def delete_todo(todo_id):
    """Delete a TODO item for the logged-in user."""
    # Access the shetchlist.db to help delete the data from the database.
    db = get_db()
    db.execute("DELETE FROM todo WHERE id = ? AND user_id = ?", (todo_id, session["user_id"]))
    db.commit()

    flash("Todo deleted.")
    return redirect(url_for("index"))

# Allow user to edit a todo item if user desires.
@app.route("/edit/<int:todo_id>", methods=["GET", "POST"])
@login_required
def edit_todo(todo_id):
    db = get_db()

    if request.method == "POST":
        # Initialize variables to be used in app.route.
        description = request.form.get("description")
        drawing = request.form.get("drawing_data")
        title = request.form.get("title")

        # Handle edge case: drawing might come in as a list
        if isinstance(drawing, list):
            drawing = drawing[0]

        if not title:
            flash("Please provide a title for todo.")
            return render_template("edit.html", todo={"id": todo_id, "title": title,
                                                      "description": description})

        # Decode base64 image to binary blob if present.
        if drawing and drawing.startswith("data:image"):
            header,encoded = drawing.split(",", 1)
            drawing_blob = base64.b64decode(encoded)
        else:
            drawing_blob = None

        db.execute("""
            UPDATE todo
            SET title = ?, description = ?, drawing = ?, updated = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
        """, (title, description, drawing_blob, todo_id, session["user_id"]))
        db.commit()
        flash("Todo updated.")
        return redirect(url_for("index"))

    # GET: fetch todo to pre-populate the form
    todo = db.execute("SELECT * FROM todo WHERE id = ? AND user_id = ?",
                      (todo_id, session["user_id"])).fetchone()
    if not todo:
        return redirect(url_for("index"))
    
    # Convert BLOB to base64 for rendering.
    if todo["drawing"]:
        drawing_data = f"data:image/png;base64,{base64.b64encode(todo['drawing']).decode('utf-8')}"
    else:
        drawing_data = ""

    return render_template("edit.html", todo=todo, drawing_data=drawing_data)

# Login user to gain access into their profile.
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user into SketchList. If the password is forgotten,
    allow login using a security question."""

    # Forget any previous users.
    session.clear()
    db = get_db()
    # Once the login form is posted by user.
    if request.method == "POST":
        action = request.form.get("action")
        # Path flow used only if password is forgotten.
        if action == "get_question":
            identifier = request.form.get("identifier")
            # Logic for security question to help user if password forgotten.
            user = db.execute("SELECT * FROM logins WHERE email = ? or username = ?",
                               (identifier, identifier)).fetchone()

            if user:
                question = user["security_question"]
                return render_template("login.html", question=question, identifier=identifier)
            else:
                flash("Account not found.")
                return redirect(url_for("login"))

        elif action == "security_answer":
            # Verify that the answer given is correct so as to give access into account.
            answer = request.form.get("security_answer")
            identifier = request.form.get("identifier")
            user = db.execute("SELECT * FROM logins WHERE email = ? or username = ?",
                               (identifier, identifier)).fetchone()

            if user:
                # Hash the given answer and check aginst already existing answer.
                answer = hashlib.sha256(answer.encode()).hexdigest()
                if answer == user["security_answer"]:
                # When successfully logged in.
                    session["user_id"] = user["id"]
                    flash("Login successful.")
                    return redirect(url_for("index"))
                else:
                    flash("Incorrect answer")
                    return redirect("/login")
            else:
                flash("User not found.")
                return redirect("/login")
        # Standard login path for user.
        else:
            identifier = request.form.get("identifier")
            password = request.form.get("passwordLogin")

            # Ensure that user gives input.
            if not identifier or not password:
                flash("Email/username or password required.")
                return render_template("login.html")
        
            # Check if identifier is in sketchlist.db.
            if "@" in identifier:
                user = db.execute("SELECT * FROM logins WHERE email = ?", (identifier,)).fetchone()
            else:
                user = db.execute("SELECT * FROM logins WHERE username = ?", (identifier,)).fetchone()

            if user and check_password_hash(user["password"], password):
                session["user_id"] = user["id"]
                flash("Login success.")
                return redirect(url_for("index"))
            else:
                flash("Invalid login details.")
                return redirect (url_for("login"))
    
    return render_template("login.html")

# Have user logout if they pleaase.
@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    return redirect(url_for("login"))

# Feature to have todo list marked as either completed or not.
@app.route("/toggle/<int:todo_id>")
@login_required
def toggle_todo(todo_id):
    """Allow user to be able to switch the status of their todo from completed or not"""
    # Use sketchlist.db to get activity and check on the status.
    db = get_db()
    todo = db.execute("SELECT completed FROM todo WHERE id = ? AND user_id = ?",
                      (todo_id, session["user_id"])).fetchone()
    if todo:
        new_status = 0 if todo["completed"] else 1
        # Update new status
        db.execute("UPDATE todo SET completed = ?, updated = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
                   (new_status, todo_id, session["user_id"]))
        db.commit()
    return redirect(url_for("index"))

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Have user register if they do not have an account. Help user with a forgot login information 
    option using security information from user that can be used later.
    Remember to hash security information.
    """
    # Clear previous session.
    session.clear()

    # When the register form is posted by user.
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        question = request.form.get("security_question")
        secure_answer = request.form.get("security_answer")
        password_error = valid_password(password)

        # Make sure user has entered needed information.
        if not email:
            flash("Email required.")
            return render_template("register.html")
        if not username:
            flash("Username required.")
            return render_template("register.html")
        if password_error:
            flash(password_error)
            return render_template("register.html")
        if not password or password != confirm:
            flash("Passwords must match.")
            return render_template("register.html")
        if not question:
            flash("Select one security question.")
            return render_template("register.html")
        if not secure_answer:
            flash("Provide answer for the security question.")
            return render_template("register.html")
        else:
            # Hash the answer provided by user.
            answer = hashlib.sha256(secure_answer.encode()).hexdigest()
        # Hash the password as long as the two passwords match.
        if password == confirm:
            password = generate_password_hash(password)
        else:
             flash("Passwords must match.")
                
        # Check if info given already exists in the database.
        db = get_db()
        identifier = db.execute("SELECT * FROM logins WHERE email = ? or username = ?", (email, username)).fetchone()
        if identifier:
         flash("Email or username already exists.")
         return render_template("register.html")

        db.execute("""INSERT INTO logins (email, username, password, security_question, security_answer)
                   VALUES (?, ?, ?, ?, ?)""",
                    (email, username, password, question, answer))
        db.commit()
        flash("Account created. Please login")
        return redirect(url_for("login"))
    else:
        return render_template("register.html")

# Accounts for different timezone.
@app.route("/set-timezone", methods=["POST"])
def set_timezone():
    data = request.get_json()
    session["timezone"] = data.get("timezone")
    return "", 204

# Run the APP
if __name__ == "__main__":
    if not os.path.exists("sketchlist.db"):
        with sqlite3.connect("sketchlist.db") as db:
            with open("schema.sql") as f:
                db.executescript(f.read())
    app.run(debug=True)