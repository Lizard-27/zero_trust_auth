from app import create_app
from flask import render_template

app = create_app()

@app.route("/")
def home():
    return render_template("home.html")

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)