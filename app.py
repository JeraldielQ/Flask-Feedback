from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import Feedback, connect_db, User, db
from flask_bcrypt import bcrypt
from forms import RegisterForm, LoginForm, FeedbackForm

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///auth_demo"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


connect_db(app)
app.app_context().push()


toolbar = DebugToolbarExtension(app)


@app.route('/')
def home_page():
    feedbacks = Feedback.query.all()
    return render_template('pages/index.html', feedbacks=feedbacks)


@app.route('/feedback', methods=['GET', 'POST'])
def show_feedback_post():
    if 'username' not in session:
        flash("Please login first!")
        return redirect('/')
    return render_template("feeback.html")


@app.route('/register', methods=['GET', 'POST'])
def register_user():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data

        user = User.register(username, password, first_name, last_name, email)

        db.session.add(user)
        db.session.commit()

        session['username'] = username

        flash("Nice!")
        return redirect('/')  # Redirect to the home page

    return render_template('pages/register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            session['username'] = username
            # Redirect to the user's profile page
            return redirect(f'/users/{username}')

        else:
            form.username.errors = ['Invalid username/password']

    return render_template('pages/login.html', form=form)


@app.route('/logout')
def logout_user():
    session.pop('username')
    return redirect('/login')


@app.route('/users/<username>')
def show_user(username):
    # Check if the user is authenticated by checking the 'username' in session
    if 'username' in session:
        user = User.query.get(username)
        if user:
            feedback = Feedback.query.filter_by(username=username).all()
            return render_template('pages/user.html', user=user, feedback=feedback)
        else:
            flash("User not found.")
            return redirect('/login')
    else:
        return redirect('/login')


@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    # Check if the user is authenticated by checking the 'username' in session
    if 'username' in session and session['username'] == username:
        user = User.query.get(username)
        if user:
            # Delete all feedback associated with the user
            Feedback.query.filter_by(username=username).delete()
            # Delete the user
            db.session.delete(user)
            db.session.commit()
            session.pop('username')
            return redirect('/')
        else:
            flash("User not found.")
            return redirect('/login')
    else:
        return redirect('/login')


@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    # Check if the user is authenticated by checking the 'username' in session
    if 'username' in session and session['username'] == username:
        form = FeedbackForm()
        if form.validate_on_submit():
            title = form.title.data
            content = form.content.data

            feedback = Feedback(
                title=title, content=content, username=username)
            db.session.add(feedback)
            db.session.commit()
            return redirect(f'/users/{username}')

        return render_template('feedback/add_feedback.html', form=form)
    else:
        return redirect('/login')


@app.route('/feedback/<feedback_id>/update', methods=['GET', 'POST'])
def update_feedback(feedback_id):
    feedback = Feedback.query.get(feedback_id)
    # Check if the user is authenticated and the feedback belongs to the user
    if 'username' in session and feedback and feedback.username == session['username']:
        form = FeedbackForm(obj=feedback)
        if form.validate_on_submit():
            feedback.title = form.title.data
            feedback.content = form.content.data
            db.session.commit()
            return redirect(f'/users/{feedback.username}')

        return render_template('feedback/update_feedback.html', form=form)
    else:
        return redirect('/login')


@app.route('/feedback/<feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get(feedback_id)
    # Check if the user is authenticated and the feedback belongs to the user
    if 'username' in session and feedback and feedback.username == session['username']:
        db.session.delete(feedback)
        db.session.commit()
        return redirect(f'/users/{feedback.username}')
    else:
        return redirect('/login')
