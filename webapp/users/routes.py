from flask import render_template, url_for, flash, redirect, request, Blueprint, abort
from flask_login import login_user, current_user, logout_user, login_required
from webapp import db, bcrypt
from webapp.users.models import User
from webapp.users.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
                                RequestResetForm, ResetPasswordForm, ChangeUserRoleAdminForm, ChangeUserRoleModeratorForm)
from webapp.users.utils import save_picture, send_reset_email
from webapp.utils import get_response_message
users = Blueprint('users', __name__)


@users.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(get_response_message('users', 'register', 'success', ''), 'success')
        return redirect(url_for('main.home'))
    return render_template('register.html', title='Register', form=form)


@users.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash(get_response_message('users', 'login', 'success', ''), 'success')
            return redirect(next_page) if next_page else redirect(url_for('main.home'))
        else:
            flash(get_response_message('users', 'login', 'failure', ''), 'danger')
    return render_template('login.html', title='Login', form=form)


@users.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('main.home'))


@users.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash(get_response_message('users', 'update', 'success', ''), 'success')
        return redirect(url_for('users.account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file, form=form)


@users.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash(get_response_message('users', 'reset', 'success', 'email_sent'), 'info')
        return redirect(url_for('users.login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@users.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash(get_response_message('users', 'reset', 'failure' 'invalid_email'), 'warning')
        return redirect(url_for('users.reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash(get_response_message('users', 'reset', 'success', 'password_updated'), 'success')
        return redirect(url_for('users.login'))
    return render_template('reset_token.html', title='Reset Password', form=form)


@users.route("/admin", methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            users = User.query.order_by(User.role)
            return render_template('admin.html', title='Admin', users=users)
        else:
            flash("You are not allowed access to the admin page!")
            return redirect(url_for('main.home'))

    def delete_user(username):
        User.query.filter_by(username=username).first().delete()


@users.route("/moderator", methods=['GET', 'POST'])
@login_required
def moderator():
    if current_user.is_authenticated:
        if current_user.role == 'moderator' or current_user.role == 'admin':
            users = User.query.filter(User.role != 'admin').filter(User.role != 'moderator')
            return render_template('moderator.html', title='Moderator', users=users)
        else:
            flash("You are not allowed access to the moderator page!")
            return redirect(url_for('main.home'))


@users.route("/moderator_modify/<username>", methods=['GET', 'POST'])
@login_required
def moderator_modify(username):
    user = User.query.filter_by(username=username).first()
    if current_user.is_authenticated and (current_user.role == 'moderator' or current_user.role == 'admin') and \
            (user.role != 'moderator' and user.role != 'admin'):
        if user.role != 'moderator' and user.role != 'admin':
            image_file = url_for('static', filename='profile_pics/' + user.image_file)
            form = ChangeUserRoleModeratorForm()
            if form.validate_on_submit():
                if form.role.data:
                    user.role = form.role.data
                    db.session.commit()
                    flash("Role Updated!", "success")
                    return redirect(url_for('users.admin'))
            elif request.method == 'GET':
                form.role.data = user.role
            return render_template('admin_modify.html', form=form, image_file=image_file, title='Admin Modify', user=user)
    else:
        flash("You are not allowed access this page!")
        return redirect(url_for('main.home'))


@users.route("/admin_modify/<string:username>", methods=['GET', 'POST'])
@login_required
def admin_modify(username):
    if current_user.is_authenticated and current_user.role == 'admin':
        user = User.query.filter_by(username=username).first()
        image_file = url_for('static', filename='profile_pics/' + user.image_file)
        form = ChangeUserRoleAdminForm()
        if form.validate_on_submit():
            if form.role.data:
                user.role = form.role.data
                db.session.commit()
                flash("Role Updated!", "success")
                return redirect(url_for('users.admin'))
        elif request.method == 'GET':
            form.role.data = user.role
        return render_template('admin_modify.html', form=form, image_file=image_file, title='Admin Modify', user=user)
    else:
        flash("You are not allowed access this page!")
        return redirect(url_for('main.home'))


@users.route("/profile/<username>", methods=['GET', 'POST'])
@login_required
def profile(username):
    if current_user.is_authenticated and (current_user.role == 'user' or current_user.role == 'admin'):
        user = User.query.filter_by(username=username).first()
        image_file = url_for('static', filename='profile_pics/' + user.image_file)
        return render_template('profile.html', image_file=image_file, title=username, user=user)
    else:
        flash("You are not allowed access this page!")
        return redirect(url_for('main.home'))


@users.route("/admin_modify/<string:username>/delete", methods=['POST'])
@login_required
def delete_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    if current_user.role != 'admin':
        abort(403)
    db.session.delete(user)
    db.session.commit()
    flash('user deleted!', 'success')
    return redirect(url_for('users.admin'))

