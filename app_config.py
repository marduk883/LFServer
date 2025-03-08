from flask import Flask
app = Flask(__name__, template_folder="templates")

# MySQL connection
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:@localhost:3306/M883LFS"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Secret key for session management and flash messages
app.config["SECRET_KEY"] = "m883lfspardonccccccccccccccccccccccccasdeoasdpokaspdmdsapl"
app.config["UPLOAD_FOLDER"] = "uploads"
