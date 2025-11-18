# utils/tags.py
from models import Tag, db

def get_or_create_tag(name: str):
    name = (name or "").strip().lower()
    if not name:
        return None
    t = Tag.query.filter_by(name=name).first()
    if t:
        return t
    t = Tag(name=name)
    db.session.add(t)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        t = Tag.query.filter_by(name=name).first()
    return t
