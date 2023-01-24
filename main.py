import flask
import werkzeug.security
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, declarative_base
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
import datetime as dt
import calendar
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
from flask import abort


app = Flask(__name__)
Bootstrap(app)
ckeditor = CKEditor(app)
db = SQLAlchemy()

# Base object to create relationship patters between tables
Base = declarative_base()

# Database configuration and connection
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
db.init_app(app)


# Parent posts table
class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # Create Foreign Key, "users.id" the users refers to the tablename of Users class.
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Create reference to the objects in Users table , the "posts" refers to the post property in the User class.
    author = relationship("Users", back_populates="posts")

    # This will act like a List of Comments objects attached to each Post.
    # The "post" below refers to the post property in the Comments class.
    comments = relationship("Comments", back_populates="post")


# User table
class Users(db.Model, UserMixin, Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    # This will act like a List of BlogPost (and Comments) objects attached to each User.
    # The "author" below refers to the author property in the BlogPost (and Comments) class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments", back_populates="author")


# Comments table
class Comments(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(600))
    date = db.Column(db.String(250), nullable=False)

    # Create Foreign Key, "users.id" the users refers to the tablename of Users class.
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))

    # Create reference to the objects in Users (and BlogPost) table , the "comments" refers to the comments property in
    # the User (and BlogPost) class.
    author = relationship("Users", back_populates="comments")
    post = relationship("BlogPost", back_populates="comments")


# Initiate database
with app.app_context():
    db.create_all()


# New post form creation
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# New user form
class NewUserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign me up")


# Login form
class UserLoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")


# Comment form
class CommentForm(FlaskForm):
    comment = CKEditorField("New comment:", validators=[DataRequired()])
    submit = SubmitField("Submit")


# Login manager object creation and initialization of app to get authentications working
login_manager = LoginManager()
login_manager.init_app(app)


# Creating a function to return user object from its ID
@login_manager.user_loader
def load_user(user_id):
    user = db.session.query(Users).get(int(user_id))
    return user


# Creating an admin_only decorator to check if user has access to admin functions
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        # If id is not 1, then return abort with 403 error
        if current_user.id != 1:
            return abort(403)

        # Otherwise, continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def home():
    # Load all blog posts
    blog_content = db.session.query(BlogPost).all()
    return render_template(f"index.html", all_posts=blog_content, logged_in=current_user.is_authenticated)


@app.route('/<int:post_id>', methods=['GET', 'POST'])
def get_post(post_id):
    # Load post content filtering by post_id
    post_content = db.session.query(BlogPost).get(post_id)

    # Load post comments filtering by post_id
    post_comments = db.session.query(Comments).filter_by(post_id=post_id).all()
    print(post_comments)

    # Create a new comment in the database
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        today = f"{calendar.month_name[dt.datetime.today().month]} {dt.datetime.today().day}, {dt.datetime.today().year}"
        new_comment = Comments(
            text=comment_form.comment.data,
            date=today,
            author=current_user,
            post=post_content
        )
        db.session.add(new_comment)
        db.session.commit()

        return redirect(f'/{post_id}')

    return render_template(f"post.html",
                           post=post_content,
                           form=comment_form,
                           logged_in=current_user.is_authenticated,
                           comments=post_comments
                           )


@app.route('/new-post', methods=['GET', 'POST'])
@admin_only
def new_post():
    page_title = "New Post"
    create_form = CreatePostForm()
    if create_form.validate_on_submit():
        date = f"{calendar.month_name[dt.datetime.today().month]} {dt.datetime.today().day}, {dt.datetime.today().year}"

        post = BlogPost(
            title=create_form.title.data,
            subtitle=create_form.subtitle.data,
            author=current_user,
            img_url=create_form.img_url.data,
            body=create_form.body.data,
            date=date
        )
        db.session.add(post)
        db.session.commit()

        return redirect(url_for('home'))
    return render_template("make-post.html",
                           form=create_form,
                           heading=page_title,
                           logged_in=current_user.is_authenticated
                           )


@app.route('/edit-post', methods=['GET', 'POST'])
@admin_only
def edit_post():
    page_title = "Edit Post"
    post_id = request.args.get("post")
    post = db.session.query(BlogPost).get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body,
        submit=SubmitField("Submit Post")
    )

    if edit_form.validate_on_submit():

        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.author = current_user
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()

        print("success")

        return redirect(url_for('home'))
    return render_template("make-post.html",
                           form=edit_form,
                           heading=page_title,
                           logged_in=current_user.is_authenticated)


@app.route('/delete/<post_id>')
@admin_only
def delete(post_id):
    post = db.session.query(BlogPost).get(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('home'))


@app.route('/register', methods=['GET', 'POST'])
def new_user():
    register_form = NewUserForm()

    if register_form.validate_on_submit():

        # Creating a hash from a given password
        hash_and_salted_password = werkzeug.security.generate_password_hash(
            register_form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )

        # Check if email is already registered
        email_input = register_form.email.data
        user = db.session.query(Users).filter_by(email=email_input).first()

        if user:
            flask.flash('Email already exists. Please, try another email.')

            return redirect(url_for('new_user'))

        # If email doesn't exist in the database, it will create a new line in the Users table
        else:
            user = Users(
                email=email_input,
                password=hash_and_salted_password,
                name=register_form.name.data
            )
            db.session.add(user)
            db.session.commit()

            flask.flash('You were successfully registered.')

            return redirect(url_for('new_user'))

    return render_template('register.html', form=register_form, logged_in=current_user.is_authenticated)


@app.route('/secrets', methods=['GET'])
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name, logged_in=current_user.is_authenticated)


@app.route('/download', methods=['GET'])
@login_required
def download():
    return flask.send_from_directory(directory='static/files', path='cheat_sheet.pdf')


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = UserLoginForm()

    if login_form.validate_on_submit():
        email_input = login_form.email.data
        password_input = login_form.password.data

        # Find user by email entered.
        user = db.session.query(Users).filter_by(email=email_input).first()

        # If user not found, it will raise an error.
        if not user:
            flask.flash("Email entered doesn't exist.")

            return redirect(url_for('login'))

        else:
            # Check stored password hash against entered password hashed.
            if werkzeug.security.check_password_hash(pwhash=user.password, password=password_input):
                login_user(user)
                return redirect(url_for('home'))

            else:
                flask.flash('Incorrect password.')

                return redirect(url_for('login'))

    return render_template('login.html', form=login_form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True)
