from flask import Flask, render_template

menu = Flask(__name__)

@menu.route("/")
def main():
    registration_end = True
    election_end = True
    return render_template("menu.html", election_end=election_end, registration_end=registration_end)

if __name__ == "__main__":
    menu.run(host="127.0.0.1", port=8080, debug=True)
