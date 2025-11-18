import os
from datetime import datetime, date, timedelta
from flask import (
    Flask, abort, jsonify, render_template, redirect, send_file, session, url_for,
    flash, request
)
from flask import send_from_directory
from flask_login import (
    LoginManager, login_user, login_required, logout_user, current_user
)
from dotenv import load_dotenv
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit, join_room
from flask import session as flask_session  # keep alias if you used it elsewhere
from models import (
    GroupAnnouncement, Notification, db, User, Group, GroupMembership,
    Task, TaskRemark, GroupMessage, TaskActivity,GroupFile
)
from models import (
    Notification, db, User, Group, GroupMembership,
    Task, TaskRemark, GroupMessage, TaskActivity,
    GroupNote,          # <-- add this
)

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
import matplotlib.pyplot as plt
import io

from forms import (
    RegistrationForm, LoginForm,
    GroupForm, AddMemberForm,
    TaskForm, TaskUpdateForm,
    MessageForm
)

from werkzeug.utils import secure_filename
from pathlib import Path


load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail config (ensure MAIL_USERNAME and MAIL_PASSWORD set in env)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
# files upload config (add after existing app.config lines)
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
# optionally change to a different absolute path in production
ALLOWED_EXT = {'png','jpg','jpeg','gif','pdf','txt','md','zip','csv','xlsx','docx','pptx'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB limit (adjust if you want)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


db.init_app(app)
mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# SocketIO (manage_session=True so flask.session works in socket handlers)
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=True)

ONLINE_USERS = set()  # track which user_ids are currently online

def send_email(to, subject, body):
    msg = Message(subject, recipients=[to])
    msg.body = body
    mail.send(msg)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def safe_count(value):
    """Always return an integer count."""
    try:
        if isinstance(value, int):
            return value
        if value is None:
            return 0
        return len(value)  # list, tuple, query results
    except:
        return 0

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data.strip(), email=form.email.data.strip())
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip()).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


# -------------------------
# Socket.IO presence
# -------------------------
@socketio.on("connect")
def on_connect():
    # optional debugging
    print("Socket connected, sid:", request.sid)


@socketio.on("join")
def handle_join(data):
    """
    Mark user online and store user_id in the Socket.IO session.
    Expects: data = {"user_id": <int>}
    """
    try:
        user_id = int(data.get("user_id"))
    except Exception:
        return

    # store the user_id in the socket session (Flask-SocketIO patches flask.session)
    session['user_id'] = user_id

    # Mark user online
    ONLINE_USERS.add(user_id)

    # Join personal room (string)
    join_room(str(user_id))

    # Broadcast presence update
    emit("presence_update", {"user_id": user_id, "online": True}, broadcast=True)


@socketio.on("disconnect")
def handle_disconnect():
    user_id = session.get('user_id')
    # fallback to current_user (rare)
    if not user_id:
        try:
            user_id = current_user.id
        except Exception:
            user_id = None

    if user_id and user_id in ONLINE_USERS:
        ONLINE_USERS.discard(user_id)
        emit("presence_update", {"user_id": user_id, "online": False}, broadcast=True)


# -------------------------
# Dashboard & Groups
# -------------------------
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = GroupForm()
    # Create a new group from the dashboard
    if form.validate_on_submit():
        group = Group(
            name=form.name.data.strip(),
            description=(form.description.data or "").strip(),
            admin_id=current_user.id
        )
        db.session.add(group)
        db.session.commit()

        membership = GroupMembership(user_id=current_user.id, group_id=group.id, role='admin')
        db.session.add(membership)
        db.session.commit()

        flash('Group created successfully.', 'success')
        return redirect(url_for('dashboard'))

    memberships = GroupMembership.query.filter_by(user_id=current_user.id).all()
    user_groups = [m.group for m in memberships]
    return render_template('dashboard.html', form=form, groups=user_groups)


@app.route('/groups')
@login_required
def groups():
    memberships = GroupMembership.query.filter_by(user_id=current_user.id).all()
    user_groups = [m.group for m in memberships]
    return render_template('groups.html', groups=user_groups)


# Deadline reminders API
@app.route("/api/deadline-reminders")
@login_required
def deadline_reminders():
    today = date.today()
    soon = today + timedelta(days=1)

    tasks = Task.query.filter(
        Task.assigned_to == current_user.id,
        Task.status != 'Done',
        Task.due_date != None,
        Task.due_date >= today,
        Task.due_date <= soon
    ).all()

    result = []
    for t in tasks:
        delta = (t.due_date - today).days
        if delta == 0:
            due_human = "today"
        elif delta == 1:
            due_human = "tomorrow"
        else:
            due_human = f"in {delta} days"
        result.append({
            "id": t.id,
            "title": t.title,
            "due_date": t.due_date.isoformat(),
            "due_human": due_human
        })
    return jsonify(result)
from collections import Counter

@app.route('/groups/<int:group_id>')
@login_required
def group_detail(group_id):
    group = Group.query.get_or_404(group_id)

    # membership check
    membership = GroupMembership.query.filter_by(
        user_id=current_user.id, group_id=group_id
    ).first()
    if not membership:
        flash('You are not a member of this group.', 'danger')
        return redirect(url_for('dashboard'))

    members = [m.user for m in group.members]

    # Admin-only views
    pending_tasks = []
    overdue_tasks = []

    if current_user.id == group.admin_id:
        today = datetime.utcnow().date()

        pending_tasks = Task.query.filter(
            Task.group_id == group.id,
            Task.status != 'Done',
            Task.due_date != None,
            Task.due_date >= today
        ).all()

        overdue_tasks = Task.query.filter(
            Task.group_id == group.id,
            Task.status != 'Done',
            Task.due_date != None,
            Task.due_date < today
        ).all()

    # Kanban columns
    todo_tasks = Task.query.filter_by(group_id=group.id, status='Pending').all()
    inprogress_tasks = Task.query.filter_by(group_id=group.id, status='In Progress').all()
    done_tasks = Task.query.filter_by(group_id=group.id, status='Done').all()

    # Files
    files = GroupFile.query.filter_by(group_id=group.id)\
        .order_by(GroupFile.created_at.desc()).all()

    # Workload (assignee task count)
    assignee_counts = Counter()
    for task in group.tasks:
        if task.assignee:
            assignee_counts[task.assignee.username] += 1

    workload_data = [["User", "Tasks Assigned"]]
    for user, count in assignee_counts.items():
        workload_data.append([user, count])

    # Announcements
    announcements = GroupAnnouncement.query.filter_by(group_id=group.id) \
        .order_by(GroupAnnouncement.created_at.desc()).all()

    # ---------------- Sprint Progress Calculation ----------------
    total_tasks_count = len(group.tasks)
    done_tasks_count = len([t for t in group.tasks if t.status == "Done"])

    if total_tasks_count > 0:
        sprint_progress = int((done_tasks_count / total_tasks_count) * 100)
    else:
        sprint_progress = 0
    # --------------------------------------------------------------

    return render_template(
        "group_detail.html",
        group=group,
        members=members,
        pending_tasks=pending_tasks,
        overdue_tasks=overdue_tasks,
        todo_tasks=todo_tasks,
        inprogress_tasks=inprogress_tasks,
        done_tasks=done_tasks,               # list
        files=files,
        workload_data=workload_data,
        announcements=announcements,

        # Sprint Progress
        sprint_progress=sprint_progress,
        total_tasks_count=total_tasks_count,
        done_tasks_count=done_tasks_count
    )

@app.route('/my_dashboard')
@login_required
def my_dashboard():
    user = current_user

    # --------------------- Tasks assigned to user ---------------------
    my_tasks = Task.query.filter_by(assigned_to=user.id).all()

    pending = [t for t in my_tasks if t.status == "Pending"]
    inprogress = [t for t in my_tasks if t.status == "In Progress"]
    done = [t for t in my_tasks if t.status == "Done"]

    # --------------------- Due this week ---------------------
    today = datetime.utcnow().date()
    week_later = today + timedelta(days=7)

    due_this_week = []
    overdue = []

    for t in my_tasks:
        if not t.due_date:
            continue

        # Convert datetime → date
        due = t.due_date.date() if isinstance(t.due_date, datetime) else t.due_date

        if today <= due <= week_later:
            due_this_week.append(t)

        if due < today and t.status != "Done":
            overdue.append(t)

    # --------------------- Workload chart ---------------------
    workload_data = [["Status", "Tasks"]]
    workload_data.append(["Pending", len(pending)])
    workload_data.append(["In Progress", len(inprogress)])
    workload_data.append(["Done", len(done)])

    # --------------------- Groups & Messages ---------------------
    groups = [m.group for m in user.memberships]

    recent_messages = GroupMessage.query \
        .filter(GroupMessage.group_id.in_([g.id for g in groups])) \
        .order_by(GroupMessage.timestamp.desc()) \
        .limit(10).all()

    # --------------------- Activity Map ---------------------
    activity = {}

    # Task activity
    for t in my_tasks:
        if hasattr(t, "activities"):
            for act in t.activities:
                d = act.timestamp.date()
                activity[d] = activity.get(d, 0) + 1

    # Message activity
    for msg in recent_messages:
        d = msg.timestamp.date()
        activity[d] = activity.get(d, 0) + 1

    activity_map = {str(d): c for d, c in activity.items()}

    return render_template(
        "user_dashboard.html",
        user=user,
        pending=pending,
        inprogress=inprogress,
        done=done,
        due_this_week=due_this_week,
        overdue=overdue,
        recent_messages=recent_messages,
        workload_data=workload_data,
        activity_map=activity_map
    )


# ---------------------------
# Real-time chat socket events
# ---------------------------
@socketio.on("join_room")
def handle_join_room(data):
    group_id = data.get("group_id")
    if group_id is None:
        return
    room=str(group_id)
    join_room(str(group_id))
    print(f"{current_user.username} joined room {group_id}")


@socketio.on("send_message")
def handle_send_message(data):
    group_id = int(data["group_id"])
    msg_text = data["message"].strip()

    if not msg_text:
        return

    # Save message to DB
    new_msg = GroupMessage(
        group_id=group_id,
        user_id=current_user.id,
        message=msg_text
    )
    db.session.add(new_msg)
    db.session.commit()

    # Emit message to everyone in this group's room (for chat UI)
    emit(
        "receive_message",
        {
            "user": current_user.username,
            "message": msg_text,
            "timestamp": new_msg.timestamp.strftime("%Y-%m-%d %H:%M")
        },
        room=str(group_id)
    )

    # Push notification to all group members except sender
    memberships = GroupMembership.query.filter_by(group_id=group_id).all()
    group = Group.query.get(group_id)

    for mem in memberships:
        if mem.user_id == current_user.id:
            continue

        # in-app DB notification (optional)
        notif = Notification(
            user_id=mem.user_id,
            message=f"New message in {group.name} from {current_user.username}: {msg_text[:40]}"
        )
        db.session.add(notif)

        # realtime browser + toast to personal room
        socketio.emit(
            "new_notification",
            {
                "user_id": mem.user_id,
                "message": f"New message in {group.name} from {current_user.username}: {msg_text[:40]}..."
            },
            to=str(mem.user_id)
        )

    db.session.commit()


def create_notification(user_id, message):
    n = Notification(user_id=user_id, message=message)
    db.session.add(n)
    db.session.commit()
    if user_id == current_user.id:
        session['popup_notification'] = message


def send_email(to, subject, body):
    try:
        msg = Message(subject, recipients=[to])
        msg.body = body
        mail.send(msg)
    except Exception as e:
        print("Email Error:", e)


# -------------------------
# Group messaging route
# -------------------------
@app.route('/groups/<int:group_id>/messages', methods=['GET'])
@login_required
def group_messages(group_id):
    group = Group.query.get_or_404(group_id)

    membership = GroupMembership.query.filter_by(
        user_id=current_user.id, group_id=group.id
    ).first()

    if not membership:
        flash('You are not a member of this group.', 'danger')
        return redirect(url_for('dashboard'))

    messages = GroupMessage.query.filter_by(
        group_id=group.id
    ).order_by(GroupMessage.timestamp.asc()).all()

    form = MessageForm()

    return render_template('group_messages.html', group=group, messages=messages, form=form)


# -------------------------
# Tasks - CREATE
# -------------------------
@app.route('/groups/<int:group_id>/tasks/create', methods=['GET', 'POST'])
@login_required
def create_task(group_id):
    group = Group.query.get_or_404(group_id)

    membership = GroupMembership.query.filter_by(
        user_id=current_user.id,
        group_id=group.id
    ).first()

    if not membership:
        flash('You are not a member of this group.', 'danger')
        return redirect(url_for('dashboard'))

    form = TaskForm()

    # Populate assignee dropdown
    group_members = [m.user for m in group.members]
    if current_user.id == group.admin_id:
        form.assigned_to.choices = [(0, 'Unassigned')] + [
            (u.id, u.username) for u in group_members if u.id != current_user.id
        ]
    else:
        form.assigned_to.choices = [(0, 'Assign to self only')]

    if form.validate_on_submit():

        # If 0 → means unassigned, fallback to assigning to the creator
        assigned_to = (
            form.assigned_to.data if form.assigned_to.data != 0
            else current_user.id
        )

        # Fetch assigned user safely
        assigned_user = User.query.get(assigned_to) if assigned_to else None

        # Non-admin cannot assign tasks to others
        if current_user.id != group.admin_id and assigned_to != current_user.id:
            flash('You cannot assign tasks to others.', 'danger')
            return redirect(url_for('group_detail', group_id=group.id))

        # Create the task
        task = Task(
            title=form.title.data.strip(),
            description=(form.description.data or "").strip(),
            created_by=current_user.id,
            assigned_to=assigned_to,
            group_id=group.id,
            due_date=form.due_date.data,
            priority=form.priority.data,
            status='Pending'
        )

        db.session.add(task)
        db.session.commit()
        # --- SEND EMAIL WHEN A USER IS ASSIGNED A TASK ---
        if task.assignee:       # OR task.assigned_to depending on your model
            send_email(
        task.assignee.email,  
        "You have been assigned a new task",
        f"You were assigned: {task.title}\n"
        f"Group: {group.name}\n"
        f"Deadline: {task.due_date or 'No deadline'}"
            )


        # ===== TaskActivity: task created =====
        try:
            activity = TaskActivity(task_id=task.id, message=f"Task created by {current_user.username}")
            db.session.add(activity)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print("TaskActivity create log error:", e)

        # ===== TaskActivity: assigned =====
        if assigned_user:
            try:
                activity = TaskActivity(task_id=task.id, message=f"Assigned to {assigned_user.username}")
                db.session.add(activity)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print("TaskActivity assigned log error:", e)

        # --------------------------
        # In-App Notification (DB)
        # --------------------------
        if assigned_user:
            notif = Notification(
                user_id=assigned_user.id,
                message=f"You have been assigned a new task: {task.title}"
            )
            db.session.add(notif)
            db.session.commit()

            # REALTIME PUSH NOTIFICATION (personal room)
            socketio.emit(
                "new_notification",
                {
                    "user_id": assigned_user.id,
                    "message": f"You have been assigned a new task: {task.title}"
                },
                to=str(assigned_user.id)
            )

            # Email (best-effort)
            try:
                send_email(
                    to=assigned_user.email,
                    subject="New Task Assigned",
                    body=(
                        f"Hello {assigned_user.username},\n\n"
                        f"You have been assigned a new task in the group '{group.name}'.\n\n"
                        f"Title: {task.title}\n"
                        f"Description: {task.description}\n"
                        f"Priority: {task.priority}\n"
                        f"Due Date: {task.due_date}\n\n"
                        f"Please check the app for more details.\n"
                    )
                )
            except Exception as e:
                print("Email send error:", e)

        flash('Task created successfully.', 'success')
        return redirect(url_for('group_detail', group_id=group.id))

    return render_template('create_task.html', form=form, group=group)


# Lightweight join helper (if front-end emits again)
# @socketio.on("join")
# def on_join(data):
#     user_id = data.get("user_id")
#     if user_id:
#         session['user_id'] = int(user_id)
#         join_room(str(user_id))


# -------------------------
# Task detail & update (comments/status)
# -------------------------
@app.route('/groups/<int:group_id>/tasks/<int:task_id>', methods=['GET', 'POST'])
@login_required
def task_detail(group_id, task_id):
    group = Group.query.get_or_404(group_id)
    task = Task.query.get_or_404(task_id)

    membership = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group.id).first()
    if not membership:
        flash('You are not a member of this group.', 'danger')
        return redirect(url_for('dashboard'))

    # prefill form from task
    form = TaskUpdateForm(obj=task)
    can_update = (current_user.id == task.assigned_to) or (current_user.id == group.admin_id)

    if form.validate_on_submit() and can_update:
        # detect and log status change
        try:
            old_status = task.status
        except Exception:
            old_status = None

        # Update status if present in form
        if hasattr(form, 'status') and form.status.data:
            new_status = form.status.data
            if new_status != task.status:
                task.status = new_status
                try:
                    act_msg = f"Status changed from '{old_status}' → '{task.status}' by {current_user.username}"
                    db.session.add(TaskActivity(task_id=task.id, message=act_msg))
                except Exception as e:
                    print("TaskActivity status log error:", e)

        # If form contains due_date, log due date change
        if hasattr(form, 'due_date') and form.due_date.data is not None:
            new_due = form.due_date.data
            if task.due_date != new_due:
                try:
                    act_msg = f"Due date updated to {new_due}"
                    db.session.add(TaskActivity(task_id=task.id, message=act_msg))
                    task.due_date = new_due
                except Exception as e:
                    print("TaskActivity due date log error:", e)

        # Save remark/comment
        remark_text = None
        if hasattr(form, 'comment') and form.comment.data:
            remark_text = form.comment.data.strip()
            remark = TaskRemark(task_id=task.id, user_id=current_user.id, comment=remark_text)
            db.session.add(remark)
            try:
                db.session.add(TaskActivity(task_id=task.id, message=f"{current_user.username} commented"))
            except Exception as e:
                print("TaskActivity comment log error:", e)

        db.session.commit()
        flash('Task updated successfully.', 'success')
        return redirect(url_for('task_detail', group_id=group.id, task_id=task.id))

    remarks = TaskRemark.query.filter_by(task_id=task.id).order_by(TaskRemark.timestamp.desc()).all()
    # load activities (latest first)
    activities = TaskActivity.query.filter_by(task_id=task.id).order_by(TaskActivity.timestamp.desc()).all()
    return render_template('task_detail.html', group=group, task=task, form=form, remarks=remarks, can_update=can_update, activities=activities)


# -------------------------
# Kanban drag/drop status update
# -------------------------
@app.route('/task/update_status', methods=['POST'])
@login_required
def update_task_status():
    data = request.get_json()
    task_id = data.get("id")
    new_status = data.get("status")

    task = Task.query.get_or_404(task_id)
    prev_status = task.status

    # Map a few tokens to canonical statuses
    if new_status in ("_todo", "todo", "Pending"):
        task.status = "Pending"
    elif new_status in ("_inprogress", "in-progress", "In Progress"):
        task.status = "In Progress"
    elif new_status in ("_done", "done", "Done"):
        task.status = "Done"
    else:
        # unknown token: set as-is
        task.status = new_status

    try:
        db.session.add(TaskActivity(
            task_id=task.id,
            message=f"Status changed from '{prev_status}' → '{task.status}' by {current_user.username}"
        ))
    except Exception as e:
        print("TaskActivity kanban update log error:", e)

    db.session.commit()

    return {"success": True}


# -------------------------
# Notifications page and context processor
# -------------------------
@app.route("/notifications")
@login_required
def notifications():
    notifs = Notification.query.filter_by(user_id=current_user.id)\
                               .order_by(Notification.timestamp.desc())\
                               .all()
    return render_template("notifications.html", notifications=notifs)


@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        unread = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
        return dict(unread_notifications=unread)
    return dict(unread_notifications=[])


# -------------------------
# Calendar events API (unchanged)
# -------------------------
@app.route('/api/tasks/events')
@login_required
def task_events():
    tasks = Task.query.filter_by(assigned_to=current_user.id).all()

    events = []
    today = datetime.utcnow().date()

    for task in tasks:
        def to_iso(obj):
            if obj is None:
                return None
            if isinstance(obj, date) and not isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, datetime):
                if obj.tzinfo is None:
                    return obj.isoformat() + 'Z'
                return obj.isoformat()
            return str(obj)

        start = None
        end = None
        all_day = False

        if getattr(task, 'due_date', None):
            if isinstance(task.due_date, date) and not isinstance(task.due_date, datetime):
                start = to_iso(task.due_date)
                end = None
                all_day = True
            else:
                start = to_iso(task.created_at) if getattr(task, 'created_at', None) else to_iso(task.due_date)
                end = to_iso(task.due_date)
                all_day = False
        else:
            if getattr(task, 'created_at', None):
                start = to_iso(task.created_at)
                all_day = False
            else:
                start = None

        color = None
        if task.status == 'done':
            color = '#2ecc71'
        elif task.status == 'in_progress':
            color = '#f39c12'
        else:
            color = '#3498db'

        if getattr(task, 'due_date', None):
            try:
                due = task.due_date
                if isinstance(due, datetime):
                    due_date_only = due.date()
                else:
                    due_date_only = due
                if due_date_only < today and task.status != 'done':
                    color = '#e74c3c'
                elif due_date_only == today and task.status != 'done':
                    color = '#f1c40f'
            except Exception:
                pass

        event = {
            'id': task.id,
            'title': f"{task.title} ({task.status})",
            'start': start,
            'end': end,
            'allDay': all_day,
            'url': url_for('task_detail', group_id=task.group_id, task_id=task.id),
            'backgroundColor': color,
            'borderColor': color,
        }
        events.append(event)

    return jsonify(events)

@socketio.on("join_group_room")
def join_group_room(data):
    group_id = data.get("group_id")
    if group_id:
        join_room(str(group_id))
        print(f"Joined Pomodoro room {group_id}")


# -------------------------
# Task activity heatmap API
# -------------------------
@app.route("/api/task-heatmap")
@login_required
def task_heatmap():
    """
    Returns a dict of activity counts per date for a given task.
    Expects: /api/task-heatmap?task_id=<int>
    Only group members may retrieve this.
    """
    task_id = request.args.get("task_id", type=int)
    if not task_id:
        return jsonify({})

    task = Task.query.get(task_id)
    if not task:
        return jsonify({})

    # security: ensure current_user is a member of the task's group
    membership = GroupMembership.query.filter_by(
        user_id=current_user.id, group_id=task.group_id
    ).first()
    if not membership:
        # Not authorized to see this task's heatmap
        return jsonify({}), 403

    # Count activities per date (ISO yyyy-mm-dd)
    activities = TaskActivity.query.filter_by(task_id=task.id).all()
    heatmap = {}
    for a in activities:
        if not getattr(a, "timestamp", None):
            continue
        key = a.timestamp.date().isoformat()
        heatmap[key] = heatmap.get(key, 0) + 1

#     return jsonify(heatmap)
# @socketio.on("start_pomodoro")
# def start_pomodoro(data):
#     task_id = data.get("task_id")
#     group_id = data.get("group_id")
#     minutes = data.get("minutes", 25)  # CUSTOM DURATION SUPPORT

#     task = Task.query.get(task_id)
#     if not task:
#         return

#     # Ensure user belongs to this group
#     membership = GroupMembership.query.filter_by(
#         user_id=current_user.id,
#         group_id=group_id
#     ).first()
#     if not membership:
#         return

#     # Set timer
#     task.pomodoro_active = True
#     task.pomodoro_end = datetime.utcnow() + timedelta(minutes=minutes)
#     task.status = "In Progress"

#     db.session.add(TaskActivity(
#         task_id=task_id,
#         message=f"{current_user.username} started a {minutes}-minute Pomodoro session"
#     ))
#     db.session.commit()

#     emit("pomodoro_update", {
#         "task_id": task_id,
#         "status": "started",
#         "ends_at": task.pomodoro_end.isoformat(),
#         "minutes": minutes,
#         "user": current_user.username
#     }, room=str(group_id))

# # @socketio.on("start_pomodoro")
# # def start_pomodoro(data):
# #     task_id = data.get("task_id")
# #     group_id = data.get("group_id")
# #     minutes = int(data.get("minutes", 25))  # <— FIX

# #     task = Task.query.get(task_id)
# #     if not task:
# #         return

# #     task.pomodoro_active = True
# #     task.pomodoro_end = datetime.utcnow() + timedelta(minutes=minutes)
# #     task.status = "In Progress"

# #     db.session.add(TaskActivity(
# #         task_id=task_id,
# #         message=f"{current_user.username} started a Pomodoro ({minutes} min)"
# #     ))
# #     db.session.commit()

# #     emit("pomodoro_update", {
# #         "task_id": task_id,
# #         "status": "started",
# #         "ends_at": task.pomodoro_end.isoformat(),
# #         "minutes": minutes,
# #         "user": current_user.username
# #     }, room=str(group_id))


# @socketio.on("stop_pomodoro")
# def stop_pomodoro(data):
#     task_id = data.get("task_id")
#     group_id = data.get("group_id")

#     task = Task.query.get(task_id)
#     if not task:
#         return

#     task.pomodoro_active = False
#     task.pomodoro_end = None

#     db.session.add(TaskActivity(
#         task_id=task_id,
#         message=f"{current_user.username} stopped the Pomodoro"
#     ))
#     db.session.commit()

#     emit("pomodoro_update", {
#         "task_id": task_id,
#         "status": "stopped",
#         "user": current_user.username
#     }, room=str(group_id))
# the second added one 

# @socketio.on("start_pomodoro")
# def start_pomodoro(data):
#     print("Received start_pomodoro:", data)  # DEBUG

#     task_id = data.get("task_id")
#     group_id = data.get("group_id")
#     minutes = int(data.get("minutes", 25))

#     task = Task.query.get(task_id)
#     if not task:
#         print("Task not found")
#         return

#     membership = GroupMembership.query.filter_by(
#         user_id=current_user.id,
#         group_id=group_id
#     ).first()

#     if not membership:
#         print("User not member of group")
#         return

#     # set timer
#     task.pomodoro_active = True
#     task.pomodoro_end = datetime.utcnow() + timedelta(minutes=minutes)
#     task.status = "In Progress"

#     db.session.add(TaskActivity(
#         task_id=task_id,
#         message=f"{current_user.username} started a {minutes}-minute Pomodoro"
#     ))
#     db.session.commit()

#     socketio.emit(
#         "pomodoro_update",
#         {
#             "task_id": task_id,
#             "status": "started",
#             "ends_at": task.pomodoro_end.isoformat(),
#             "minutes": minutes,
#             "user": current_user.username
#         },
#         room=str(group_id)
#     )
#     print("Emitted pomodoro_update to room", group_id)

####
# @socketio.on("start_pomodoro")
# def start_pomodoro(data):
#     print("Received start_pomodoro:", data)

#     task_id = data.get("task_id")
#     group_id = data.get("group_id")
#     minutes = int(data.get("minutes", 25))

#     task = Task.query.get(task_id)
#     if not task:
#         print("Task not found")
#         return

#     membership = GroupMembership.query.filter_by(
#         user_id=current_user.id,
#         group_id=group_id
#     ).first()

#     if not membership:
#         print("User not member of group")
#         return

#     # Set timer
#     task.pomodoro_active = True
#     task.pomodoro_end = datetime.utcnow() + timedelta(minutes=minutes)
#     task.status = "In Progress"

#     db.session.add(TaskActivity(
#         task_id=task_id,
#         message=f"{current_user.username} started a {minutes}-minute Pomodoro"
#     ))
#     db.session.commit()

#     # IMPORTANT: send to correct room
#     socketio.emit(
#         "pomodoro_update",
#         {
#             "task_id": task_id,
#             "status": "started",
#             "ends_at": task.pomodoro_end.isoformat() + "Z",
#             "minutes": minutes,
#             "user": current_user.username
#         },
#         room=str(group_id)  # FIXED — frontend joins this room
#     )

#     print("Pomodoro started — emitted to room", group_id)

# # @socketio.on("stop_pomodoro")
# def stop_pomodoro(data):
#     print("Received stop_pomodoro:", data)

#     task_id = data.get("task_id")
#     group_id = data.get("group_id")

#     task = Task.query.get(task_id)
#     if not task:
#         return

#     task.pomodoro_active = False
#     task.pomodoro_end = None

#     db.session.add(TaskActivity(
#         task_id=task_id,
#         message=f"{current_user.username} stopped the Pomodoro"
#     ))
#     db.session.commit()

#     # IMPORTANT: send to correct room
#     socketio.emit(
#         "pomodoro_update",
#         {
#             "task_id": task_id,
#             "status": "stopped",
#             "user": current_user.username
#         },
#         room=str(group_id)  # FIXED
#     )

#     print("Pomodoro stopped — emitted to room", group_id)


# -------------------------
# Group-level heatmap API
# -------------------------
@app.route("/api/group-heatmap")
@login_required
def group_heatmap():
    """
    Returns aggregated counts per date for a group.
    Query params:
      - group_id (required)
      - type = "activity" | "deadline" | "both"  (default "both")
      - months = integer number of months to include (default 12)
    Response:
      { "YYYY-MM-DD": { "activity": n, "deadline": m }, ... }
    """
    try:
        group_id = int(request.args.get("group_id"))
    except Exception:
        return jsonify({}), 400

    mode = request.args.get("type", "both")
    months = int(request.args.get("months", 12))

    group = Group.query.get(group_id)
    if not group:
        return jsonify({}), 404

    # security check: only group members may fetch
    membership = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if not membership:
        return jsonify({}), 403

    # compute date range: from first day of (months-1) months ago to end of current month
    today = date.today()
    # compute first month start
    start_month = today.month - (months - 1)
    start_year = today.year
    # roll over years if necessary
    while start_month <= 0:
        start_month += 12
        start_year -= 1
    start_date = date(start_year, start_month, 1)
    # end_date = last day of current month
    end_date = date(today.year, today.month, (date(today.year, today.month + 1, 1) - timedelta(days=1)).day) \
        if today.month < 12 else date(today.year, 12, 31)

    # safer: build end_date as last day of current month:
    last_day_current_month = (date(today.year, today.month + 1, 1) - timedelta(days=1)) if today.month < 12 else date(today.year, 12, 31)
    end_date = last_day_current_month

    # prepare result dict of date -> {activity:0, deadline:0}
    delta_days = (end_date - start_date).days
    result = {}
    for i in range(delta_days + 1):
        d = start_date + timedelta(days=i)
        result[d.isoformat()] = {"activity": 0, "deadline": 0}

    # deadlines: count tasks whose due_date falls in range
    if mode in ("deadline", "both"):
        tasks_with_due = Task.query.filter(
            Task.group_id == group_id,
            Task.due_date != None,
            Task.due_date >= start_date,
            Task.due_date <= end_date
        ).all()
        for t in tasks_with_due:
            # normalize due_date to date only
            dd = t.due_date
            if isinstance(dd, datetime):
                dd = dd.date()
            s = dd.isoformat()
            if s in result:
                result[s]["deadline"] += 1

    # activity: count TaskActivity rows for tasks in this group
    if mode in ("activity", "both"):
        # get task ids in this group
        task_ids = [t.id for t in Task.query.filter_by(group_id=group_id).all()]
        if task_ids:
            activities = TaskActivity.query.filter(TaskActivity.task_id.in_(task_ids))\
                                           .filter(TaskActivity.timestamp >= datetime.combine(start_date, datetime.min.time()))\
                                           .filter(TaskActivity.timestamp <= datetime.combine(end_date, datetime.max.time()))\
                                           .all()
            for a in activities:
                if not getattr(a, "timestamp", None):
                    continue
                key = a.timestamp.date().isoformat()
                if key in result:
                    result[key]["activity"] += 1

    return jsonify(result)


#timer part 

@socketio.on("start_pomodoro")
def start_pomodoro(data):
    print("Received start_pomodoro:", data)

    task_id = data.get("task_id")
    group_id = data.get("group_id")
    minutes = int(data.get("minutes", 25))

    task = Task.query.get(task_id)
    if not task:
        print("Task not found")
        return

    membership = GroupMembership.query.filter_by(
        user_id=current_user.id,
        group_id=group_id
    ).first()

    if not membership:
        print("User not member of group")
        return

    task.pomodoro_active = True
    task.pomodoro_end = datetime.utcnow() + timedelta(minutes=minutes)
    task.status = "In Progress"

    db.session.add(TaskActivity(
        task_id=task_id,
        message=f"{current_user.username} started a {minutes}-minute Pomodoro"
    ))
    db.session.commit()

    # 🔥 FIX — append "Z" so JS parses correctly
    ends_at_iso = task.pomodoro_end.isoformat() + "Z"

    socketio.emit(
        "pomodoro_update",
        {
            "task_id": task_id,
            "status": "started",
            "ends_at": ends_at_iso,
            "minutes": minutes,
            "user": current_user.username
        },
        room=str(group_id)
    )
    print("Emitted pomodoro_update:", ends_at_iso)


@socketio.on("stop_pomodoro")
def stop_pomodoro(data):
    print("Received stop_pomodoro:", data)

    task_id = data.get("task_id")
    group_id = data.get("group_id")

    task = Task.query.get(task_id)
    if not task:
        return

    task.pomodoro_active = False
    task.pomodoro_end = None

    db.session.add(TaskActivity(
        task_id=task_id,
        message=f"{current_user.username} stopped the Pomodoro"
    ))
    db.session.commit()

    socketio.emit(
        "pomodoro_update",
        {
            "task_id": task_id,
            "status": "stopped",
            "user": current_user.username
        },
        room=str(group_id)
    )
    print("Emitted pomodoro stopped")

@app.route("/group/<int:group_id>/export_report")
@login_required
def export_report(group_id):
    group = Group.query.get_or_404(group_id)

    # Only members can export
    membership = GroupMembership.query.filter_by(
        group_id=group_id, user_id=current_user.id
    ).first()
    if not membership:
        abort(403)

    # Collect data
    tasks = Task.query.filter_by(group_id=group_id).all()
    activities = TaskActivity.query.join(Task).filter(Task.group_id == group_id).all()

    # Prepare PDF buffer
    buffer = io.BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=A4)

    styles = getSampleStyleSheet()
    story = []

    # ----- TITLE -----
    story.append(Paragraph(f"<b>Project Report – {group.name}</b>", styles["Title"]))
    story.append(Spacer(1, 12))

    # ----- SUMMARY -----
    story.append(Paragraph("<b>Tasks by Status</b>", styles["Heading2"]))
    status_counts = {}
    for t in tasks:
        status_counts[t.status] = status_counts.get(t.status, 0) + 1

    for status, count in status_counts.items():
        story.append(Paragraph(f"{status}: {count}", styles["Normal"]))

    story.append(Spacer(1, 12))

    # ----- DUE DATES -----
    story.append(Paragraph("<b>Due Dates</b>", styles["Heading2"]))
    due_sorted = sorted([t for t in tasks if t.due_date], key=lambda x: x.due_date)

    for t in due_sorted:
        story.append(Paragraph(
            f"{t.title}: {t.due_date.strftime('%Y-%m-%d')}",
            styles["Normal"]
        ))
    story.append(Spacer(1, 12))

    # ----- BURNDOWN CHART -----
    story.append(Paragraph("<b>Burndown Chart</b>", styles["Heading2"]))

    # Generate burndown chart
    completed = []
    total = len(tasks)
    days = list(range(1, total + 1))

    done = 0
    for i in range(len(tasks)):
        t = tasks[i]
        if t.status.lower() == "completed":
            done += 1
        completed.append(total - done)

    # Plot chart
    fig, ax = plt.subplots(figsize=(4, 3))
    ax.plot(days, completed, marker="o")
    ax.set_title("Burndown Progress")
    ax.set_xlabel("Task Index")
    ax.set_ylabel("Tasks Remaining")

    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format="png", dpi=150)
    plt.close(fig)
    img_buffer.seek(0)

    # Insert into PDF
    chart_image = Image(img_buffer, width=4 * inch, height=3 * inch)
    story.append(chart_image)
    story.append(Spacer(1, 12))

    # ----- TEAM ACTIVITY -----
    story.append(Paragraph("<b>Team Activity</b>", styles["Heading2"]))
    for a in activities:
        story.append(Paragraph(
            f"{a.timestamp.strftime('%Y-%m-%d %H:%M')} – {a.message}",
            styles["Normal"]
        ))

    # --- BUILD PDF ---
    pdf.build(story)

    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"ProjectReport_{group.name}.pdf",
        mimetype="application/pdf"
    )
# @app.route('/groups/<int:group_id>/notes', methods=['GET'])
# @login_required
# def group_notes(group_id):
#     group = Group.query.get_or_404(group_id)

#     # membership check
#     membership = GroupMembership.query.filter_by(
#         user_id=current_user.id,
#         group_id=group.id
#     ).first()
#     if not membership:
#         flash("You are not a member of this group.", "danger")
#         return redirect(url_for("dashboard"))

#     # one note per group; create if missing
#     note = GroupNote.query.filter_by(group_id=group.id).first()
#     if note is None:
#         note = GroupNote(group_id=group.id, content="")
#         db.session.add(note)
#         db.session.commit()

#     return render_template(
#         "group_notes.html",
#         group=group,
#         note=note
#     )
# @socketio.on("notes_update")
# def handle_notes_update(data):
#     """
#     Real-time shared notes per group.
#     data = { "group_id": <int>, "content": <string> }
#     """
#     group_id = data.get("group_id")
#     content = data.get("content", "")

#     if group_id is None:
#         return

#     # Ensure user is member of this group
#     membership = GroupMembership.query.filter_by(
#         user_id=current_user.id,
#         group_id=group_id
#     ).first()
#     if not membership:
#         return  # ignore non-members

#     # Upsert note
#     note = GroupNote.query.filter_by(group_id=group_id).first()
#     if note is None:
#         note = GroupNote(group_id=group_id, content=content)
#         db.session.add(note)
#     else:
#         note.content = content

#     db.session.commit()

#     # Broadcast to all sockets in this group room (except sender)
#     socketio.emit(
#         "notes_update",
#         {
#             "group_id": group_id,
#             "content": content,
#             "user_id": current_user.id,
#             "username": current_user.username,
#         },
#         room=str(group_id),
#         include_self=False
#     )

# -------------------------
# Add member (admin only)
# -------------------------
@app.route('/groups/<int:group_id>/add-member', methods=['GET', 'POST'])
@login_required
def add_member(group_id):
    group = Group.query.get_or_404(group_id)
    if current_user.id != group.admin_id:
        flash('Only the group creator can add members.', 'danger')
        return redirect(url_for('group_detail', group_id=group.id))

    form = AddMemberForm()
    existing_member_ids = [m.user_id for m in group.members]
    available_users = User.query.filter(User.id.notin_(existing_member_ids)).all()
    form.user_id.choices = [(u.id, u.username) for u in available_users]

    if form.validate_on_submit():
        user_id = form.user_id.data
        role = form.role.data
        if GroupMembership.query.filter_by(user_id=user_id, group_id=group.id).first():
            flash('User already in group.', 'warning')
            return redirect(url_for('group_detail', group_id=group.id))

        new_member = GroupMembership(user_id=user_id, group_id=group.id, role=role)
        db.session.add(new_member)
        db.session.commit()
        flash(f'User added successfully as {role}.', 'success')
        return redirect(url_for('group_detail', group_id=group.id))

    return render_template('add_member.html', group=group, form=form)
# app.py (add these helper + routes)

def allowed_file(filename):
    if not filename:
        return False
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return ext in ALLOWED_EXT

def ensure_group_upload_folder(group_id):
    folder = os.path.join(app.config['UPLOAD_FOLDER'], f"group_{group_id}")
    Path(folder).mkdir(parents=True, exist_ok=True)
    return folder
@app.route("/group/<int:group_id>/announcement", methods=["POST"])
@login_required
def post_announcement(group_id):
    group = Group.query.get_or_404(group_id)

    msg = request.form.get("message", "").strip()
    if not msg:
        return redirect(url_for("group_detail", group_id=group_id))

    ann = GroupAnnouncement(
        group_id=group.id,
        message=msg,
        author_id=current_user.id
    )

    db.session.add(ann)
    db.session.commit()

    return redirect(url_for("group_detail", group_id=group_id))

# Upload file (POST) and list files (GET)
@app.route('/groups/<int:group_id>/files', methods=['GET', 'POST'])
@login_required
def group_files(group_id):
    group = Group.query.get_or_404(group_id)

    # membership check
    membership = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group.id).first()
    if not membership:
        flash('You are not allowed to access group files.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # simple upload form: <input type=file name="file">
        if 'file' not in request.files:
            flash('No file part', 'warning')
            return redirect(url_for('group_detail', group_id=group.id))

        f = request.files['file']
        if f.filename == '':
            flash('No selected file', 'warning')
            return redirect(url_for('group_detail', group_id=group.id))

        if not allowed_file(f.filename):
            flash('File type not allowed', 'danger')
            return redirect(url_for('group_detail', group_id=group.id))

        # sanitize and build a unique stored filename
        original = secure_filename(f.filename)
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
        stored_name = f"{timestamp}_{original}"

        folder = ensure_group_upload_folder(group.id)
        full_path = os.path.join(folder, stored_name)

        try:
            f.save(full_path)
            filesize = os.path.getsize(full_path)
            gf = GroupFile(
                group_id=group.id,
                uploaded_by=current_user.id,
                filename=stored_name,
                original_filename=original,
                filesize=filesize
            )
            db.session.add(gf)
            db.session.commit()

            # activity log + optional notification
            try:
                db.session.add(TaskActivity(
                    task_id=None,
                    message=f"{current_user.username} uploaded file '{original}' to group '{group.name}'"
                ))
                db.session.commit()
            except Exception:
                db.session.rollback()

            flash('File uploaded', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.exception("File upload error")
            flash('Failed to upload file', 'danger')

        return redirect(url_for('group_detail', group_id=group.id))

    # GET -> listing
    files = GroupFile.query.filter_by(group_id=group.id).order_by(GroupFile.created_at.desc()).all()
    # If you want a dedicated template: return render_template('group_files.html', group=group, files=files)
    # but we'll integrate via group_detail; here we'll just return for caller if needed.
    return render_template('group_files.html', group=group, files=files)


# Download a file (only group members allowed)
@app.route('/groups/<int:group_id>/files/<int:file_id>/download', methods=['GET'])
@login_required
def download_group_file(group_id, file_id):
    group = Group.query.get_or_404(group_id)
    gf = GroupFile.query.get_or_404(file_id)

    # sanity: file belongs to this group
    if gf.group_id != group.id:
        flash('File not found in this group', 'danger')
        return redirect(url_for('group_detail', group_id=group.id))

    # membership check
    membership = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group.id).first()
    if not membership:
        flash('You are not allowed to download this file', 'danger')
        return redirect(url_for('dashboard'))

    folder = ensure_group_upload_folder(group.id)
    stored = gf.filename
    # check file exists
    filepath = os.path.join(folder, stored)
    if not os.path.exists(filepath):
        flash('File not available on disk', 'danger')
        return redirect(url_for('group_detail', group_id=group.id))

    # send as attachment using send_from_directory
    return send_from_directory(folder, stored, as_attachment=True, download_name=gf.original_filename)


# Shell context
@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'User': User,
        'Group': Group,
        'GroupMembership': GroupMembership
    }


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
