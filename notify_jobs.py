from app import app, db, Task, send_email
from datetime import datetime, timedelta

with app.app_context():
    tomorrow = datetime.utcnow().date() + timedelta(days=1)

    tasks = Task.query.filter(Task.due_date == tomorrow).all()

    for t in tasks:
        if t.assignee:
            send_email(
                t.assignee.email,
                "Task Deadline Reminder (Tomorrow)",
                f"Your task '{t.title}' is due tomorrow."
            )
yesterday = datetime.utcnow().date() - timedelta(days=1)

overdue = Task.query.filter(
    Task.due_date == yesterday,
    Task.status != "Done"
).all()

for t in overdue:
    if t.assignee:
        send_email(
            t.assignee.email,
            "Task is Overdue",
            f"Your task '{t.title}' was due yesterday!"
        )
