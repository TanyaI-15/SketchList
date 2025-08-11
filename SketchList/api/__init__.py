import base64, sqlite3
from flask import Blueprint, g, jsonify, session

todo_bp = Blueprint("todo_bp", __name__)

# Connect sketchlist.db to the application
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect("sketchlist.db")
    g.db.row_factory = sqlite3.Row
    return g.db

# Keep the app from leaking the open db connection
def init_app(app):
    @app.teardown_appcontext
    def close_db(error):
        db = g.pop('db', None)
        if db is not None:
            db.close()


@todo_bp.route("/api/todo")
def todo_list():
    db = get_db()
    todos = db.execute("SELECT * FROM todo WHERE user_id = ?", (session["user_id"],)).fetchall()

    todo_list = []
    for todo in todos:
        drawing_blob = todo["drawing"]
        if drawing_blob:
            drawing_base64 = base64.b64encode(drawing_blob).decode("utf-8")
            drawing_url = f"data:image/png;base64,{drawing_base64}"
        else:
            drawing_url = None

        todo_dict = dict(todo)
        todo_dict["drawing"] = drawing_url

        todo_list.append(todo_dict)

    return jsonify(todo_list)