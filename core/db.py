from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base, LogEntry, Alert

class DB:
    def __init__(self, db_url="sqlite:///siem.db"):
        self.engine = create_engine(db_url, connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def add_log(self, **kwargs):
        s = self.Session()
        e = LogEntry(**kwargs)
        s.add(e)
        s.commit()
        s.refresh(e)
        s.close()
        return e

    def add_alert(self, log_id, rule, description):
        s = self.Session()
        a = Alert(log_id=log_id, rule=rule, description=description)
        s.add(a)
        s.commit()
        s.refresh(a)
        s.close()
        return a

    def list_logs(self, limit=100):
        s = self.Session()
        res = s.query(LogEntry).order_by(LogEntry.timestamp.desc()).limit(limit).all()
        s.close()
        return res

    def list_alerts(self, limit=100):
        s = self.Session()
        res = s.query(Alert).order_by(Alert.created_at.desc()).limit(limit).all()
        s.close()
        return res
