from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

Base = declarative_base()

class LogEntry(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True)
    source = Column(String(64))
    timestamp = Column(DateTime, index=True)
    ip = Column(String(64), index=True)
    request = Column(Text)
    status_code = Column(Integer)
    bytes_sent = Column(Integer)
    meta = Column(Text)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    log_id = Column(Integer, ForeignKey("logs.id"))
    rule = Column(String(128))
    description = Column(Text)
    created_at = Column(DateTime, default=func.now())
    log = relationship("LogEntry")
