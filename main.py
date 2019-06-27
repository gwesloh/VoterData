from flask import Flask, request, redirect, render_template, session, flash
from flask_sqlalchemy import SQLAlchemy
import hashlib
import random
import string

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://voterdata:launchcode@localhost:8889/voterdata'
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)


class Task(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    task_title = db.Column(db.String(120))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, task_title, owner):
        self.task_title = task_title
        self.id= request.args.get('id')
        self.owner = owner
    
    def __repr__(self):
        return '<Task %r>' % self.task_title
    
class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True)
    pw_hash = db.Column(db.String(500))
    tasks = db.relationship('Task', backref='owner')

    def __init__(self, username, password):
        self.username = username
        self.pw_hash = make_pw_hash(password)
        self.id= request.args.get('id')
    
    def __repr__(self):
        return '<User %r>' % self.username

class Voter(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    tags = db.relationship('Tags', backref='voter')

    def __init__(self, name):
        self.name = name
        self.id= request.args.get('id')
    
    def __repr__(self):
        return '<Voter %r>' % self.name


class Tags(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    task_title = db.Column(db.String(120))
    voter_id = db.Column(db.Integer, db.ForeignKey('voter.id'))

    def __init__(self, task_title, voter):
        self.task_title = task_title
        self.id= request.args.get('id')
        self.voter = voter
    
    def __repr__(self):
        return '<Task %r>' % self.task_title


@app.route('/', methods=['GET','POST'])
def index():
    if request.method == 'POST':
        users = User.query.all()
        return render_template('index.html', users= users)
    else:
        users = User.query.all()
        return render_template('index.html', users= users)

@app.route('/tasks', methods=['GET','POST'])
def get_tasks():
    return render_template('tasks.html')

@app.route('/allvoters', methods=['GET','POST'])
def get_all_voters():
    return render_template('allvoters.html')
       
@app.route('/search', methods=['GET','POST'])
def new_post():
        return render_template('search.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = User.query.filter_by(username=username)
        if users.count() == 1:
            user = users.first()
            if check_pw_hash(password, user.pw_hash):
                session['user'] = user.username
                flash('welcome back, ' + user.username)
                return redirect("/")
            else:
                flash('Invalid Password', category= 'login_pw_error')
               
        else:
            flash('Invalid Username', category= 'login_error')
            
        return redirect("/login")

@app.route("/signup", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        verify = request.form['verify']
        is_error=False
        if not char_present(username):
            flash('oh no! Username field is blank', category= 'username_error')
            is_error= True
    
        if not char_present(password):
            flash('oh no! Password field is blank', category= 'password_error')
            is_error= True
    
        if not char_present(verify):
            flash('oh no! Verify field is blank', category= 'verify_error')
            is_error= True

        if not is_username_or_pass(username):
            flash('oh no! "' + username + '" does not seem like a username', category= 'username_error')
            is_error= True
        
        if not is_username_or_pass(password):
            flash('oh no! "' + password + '" does not seem like a password', category= 'password_error')
            is_error= True
        
        if password != verify:
            flash('passwords did not match', category= 'verify_error')
            is_error= True
        
        username_db_count = User.query.filter_by(username=username).count()
        
        if username_db_count > 0:
            flash('yikes! "' + username + '" is already taken')
            is_error= True

        if is_error:
            return render_template('signup.html', username= username)
        else:
            user = User(username=username, password=password) 
            db.session.add(user)
            db.session.commit()
            session['user'] = user.username
            return redirect("/")
    else:
        return render_template('signup.html')


def is_username_or_pass(string):
    len_test_low = len(string) >= 3
    len_test_high = len(string) <= 20
    space_index = string.find(' ')
    space_present = space_index >=0
    if not len_test_low:
        return False
    elif not len_test_high:
        return False
    elif space_present:
        return False
    else:
        return True 



def char_present(string):
    char_is_present = len(string) != 0
    if not char_is_present:
        return False
    else:
        return True

@app.route("/logout", methods=['POST'])
def logout():
    del session['user']
    return redirect("/blog")

endpoints_without_login = ['login', 'register','index','/']

@app.before_request
def require_login():
    if not (('user' in session) or (request.endpoint in endpoints_without_login)):
        return redirect("/login")



def make_salt():
    return ''.join([random.choice(string.ascii_letters) for x in range(5)])


def make_pw_hash(password, salt=None):
    if not salt:
        salt = make_salt()
    hash = hashlib.sha256(str.encode(password + salt)).hexdigest()
    return '{0},{1}'.format(hash, salt)


def check_pw_hash(password, hash):
    salt = hash.split(',')[1]
    if make_pw_hash(password, salt) == hash:
        return True

    return False

app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RU'
if __name__ == '__main__':
    app.run()