from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
from extensions import app, mail
from models import User
from forms import RegisterForm, MessageForm, LoginForm, UpdateForm, ForgotPasswordForm,ResetPasswordForm
from datetime import datetime


import pytz

georgia_tz = pytz.timezone("Asia/Tbilisi")
local_time = current_user.last_login.astimezone(georgia_tz)
formatted_time = local_time.strftime('%Y-%m-%d %H:%M:%S')
# 📌 Email ვერიფიკაციის ტოკენის გენერაცია
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# 📌 პაროლის აღდგენის როუტი
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('პაროლის აღდგენა', recipients=[user.email])
            msg.body = f"პაროლის აღსადგენად დააჭირეთ ამ ბმულს: {reset_url}"
            mail.send(msg)
            flash('ელ.ფოსტა გაგზავნილია!', 'success')
            return redirect(url_for('login'))
        else:
            flash('ამ ელ.ფოსტით მომხმარებელი არ მოიძებნა.', 'danger')
    return render_template('forgot_password.html', form=form, title="პაროლის აღდგენა - ვეფხისტყაოსანი")

# 📌 პაროლის განახლების როუტი
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)  # 1 საათი
    except (SignatureExpired, BadTimeSignature):
        flash('ბმული არასწორია ან ვადა გაუვიდა!', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('მომხმარებელი ვერ მოიძებნა!', 'danger')
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.password.data)
        db.session.commit()
        flash('პაროლი წარმატებით განახლდა!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html', title="სერვერის შეცდომა - ვეფხისტყაოსანი"), 500



def send_verification_email(user_email):
    token = generate_verification_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Email Verification"
    message_body = f"მოგესალმებით, {user.username}! 😊\n\nმადლობა, რომ დაინტერესდით ჩემი პროექტით. თქვენი ანგარიში წარმატებით შეიქმნა! გთხოვთ, გაიარეთ ვერიფიკაცია შემდეგ ბმულზე:\n\n{confirm_url}\n\nმადლობა ყურადღებისთვის! 🙌"



    msg = Message(
        subject=subject,
        recipients=[user_email],
        body=message_body,
        sender="vepkkhistyaosaniproject@gmail.com"  # ✅ დაამატე გამგზავნი!
    )

    mail.send(msg)
def generate_verification_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm')

def confirm_verification_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=expiration)
    except:
        return False
    return email

# 📌 ვერიფიკაციის იმეილის გაგზავნა
def send_verification_email(user_email):
    token = generate_verification_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Email Verification"
    message_body = f"დააჭირეთ ამ ბმულს თქვენი ემაილის ვერიფიკაციისთვის: {confirm_url}"

    msg = Message(subject=subject, recipients=[user_email], body=message_body)
    mail.send(msg)

# 📌 ვერიფიკაციის ბმულის დამუშავება
@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_verification_token(token)
    if not email:
        flash("ვერიფიკაციის ბმული არასწორია ან ვადა გაუვიდა!", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user and not user.is_verified:
        user.is_verified = True
        user.save()
        flash("თქვენი ემაილი წარმატებით ვერიფიცირდა!", "success")
    elif user and user.is_verified:
        flash("თქვენი ემაილი უკვე ვერიფიცირებულია!", "info")

    return redirect(url_for('login'))

@app.route("/admin/users")
@login_required
def view_users():
    if current_user.username == "sandroqatamadze":
        users = User.query.all()
        return render_template("admin_users.html", users=users, title="მონაცემების ხილვა")
    else:
        flash("Sorry, you are not authorized to view this page.")
        return redirect(url_for('noadmin'))

@app.route("/403")
@login_required
def noadmin():
    return render_template("403.html", title="აკრძალული წვდომა - ვეფხისტყაოსანი")

@app.route("/admin")
@login_required
def admin():
    if current_user.username == "sandroqatamadze":
        return render_template("admin.html", title="ადმინის გვერდი - ვეფხისტყაოსანი")
    else:
        flash("Sorry but you are not the admin")
        return redirect(url_for('noadmin'))

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html', title="404 - ვეფხისტყაოსანი"), 404

@app.route("/")
def index():
    return render_template("index.html", title="ვეფხისტყაოსანი")

@app.route("/update", methods=["GET", "POST"])
def update():
    form = UpdateForm()
    if form.validate_on_submit():
        print(form.update.data)
    return render_template("update.html", form=form, title="გააგრძელე - ვეფხისტყაოსანი")

@app.route("/about")
def about():
    return render_template("about.html", title="პროექტის შესახებ - ვეფხისტყაოსანი")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = MessageForm()
    if form.validate_on_submit():
        print(form.message.data)
    return render_template("contact.html", form=form, title="კონტაქტი - ვეფხისტყაოსანი")

@app.route("/author")
def author():
    return render_template("author.html", title="ავტორის შესახებ - ვეფხისტყაოსანი")

# 📌 ავტორიზაციის როუტი - მხოლოდ ვერიფიცირებული მომხმარებლებისთვის
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            if not user.is_verified:
                send_verification_email(user.email)  # ხელახალი გაგზავნა
                flash("თქვენს ელ-ფოსტაზე ვერიფიკაციის ბმული გაგზავნილია!", "warning")
                return redirect(url_for('login'))
            
            login_user(user, remember=True)  # ✅ სესიის დამახსოვრება
            user.update_last_login()  # ✅ ბოლო აქტივობის განახლება
            return redirect(url_for("index")) 
    
    return render_template("login.html", form=form, title="ავტორიზაცია - ვეფხისტყაოსანი")

@app.route("/admin/sessions")
@login_required
def admin_sessions():
    if current_user.username != "sandroqatamadze":
        flash("თქვენ არ გაქვთ წვდომა!", "danger")
        return redirect(url_for("index"))

    users = User.query.filter(User.last_login >= datetime.utcnow() - timedelta(minutes=30)).all()
    return render_template("admin_sessions.html", users=users)



@app.route("/poem")
def poem():
    return render_template("poem.html", title="პოემა - ვეფხისტყაოსანი")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", title="პროფილი - ვეფხისტყაოსანი")

# 📌 რეგისტრაციის როუტი - ემაილის ვერიფიკაციის გაგზავნით
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            birthday=form.birthday.data,
            country=form.country.data,
            gender=form.gender.data,
            is_verified=False
        )
        user.create()
        send_verification_email(user.email)
        flash("თქვენს ელფოსტაზე გაგზავნილია ვერიფიკაციის ბმული!", "info")
        return redirect(url_for("login"))
    
    print(form.errors) 
    return render_template("register.html", form=form, title="რეგისტრაცია - ვეფხისტყაოსანი")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html", title="უსაფრთხოების პოლიტიკა - ვეფხისტყაოსანი")

if __name__ == "__main__":  
    app.run(debug=True)
