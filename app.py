from flask import Flask, request, flash, url_for, redirect, render_template
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask_hashing import Hashing

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']= False
app.config['HASH_METHOD'] = 'sha512'
app.config['SECRET_KEY'] = "random string"
hashing = Hashing(app)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100))
    mobile = db.Column(db.Integer)
    username = db.Column(db.String(200))
    email = db.Column(db.String(100))
    password = db.Column(db.LargeBinary)
    
    def __init__(self, name, mobile, username, email, password):
        self.name = name
        self.mobile = mobile
        self.username = username
        self.email = email
        self.password = password

@app.route('/',methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if(request.method == 'POST'):
        db.create_all()
        username = request.form.get('username')
        password = request.form.get('password')
        users = User.query.filter_by(username = username).all()
        if(len(users) > 0):
            val_hash = hashing.hash_value(password, salt='abcd')
            if(val_hash == decrypt(users[0].password)):
                return render_template('index.html',message = "Logged In")
            else:
                return render_template('login.html',message = 'Check Your credentials')
            return render_template('login.html')
        else:
            return render_template('login.html',message = 'Check Your credentials')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    return redirect('/')

@app.route('/signup', methods=['GET','POST'])
def signup():
    if(request.method == 'POST'):
        db.create_all()
        name = request.form.get('name')
        mobile = request.form.get('mobile')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        users = User.query.all()
        for i in users:
            if(i.username == username):
                return render_template('signup.html', message = 'Username Already exists')
            if(i.email == email):
                return render_template('signup.html', message = 'Email Already exists')
        hashed = hashing.hash_value(password, salt = 'abcd')
        encrypted = encrypt(bytes(hashed, 'utf-8'))
        user = User(name = name, mobile = mobile, username = username, email = email, password = encrypted)
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    return render_template('signup.html')

if __name__ == '__main__':
   db.create_all()
   app.run(debug = True)


def encrypt(abc):
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext= cipher.encrypt(abc)
    return ciphertext
    
def decrypt(ciphertext):
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return str(plaintext)[2:-1]
