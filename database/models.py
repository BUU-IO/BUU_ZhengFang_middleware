from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from datetime import datetime

# 声明模型基类
Base = declarative_base()


# 示例用户模型
class User(Base):
    """用户数据模型"""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    # CRUD 操作方法
    @classmethod
    def create(cls, db_session: Session, **kwargs):
        """创建新用户"""
        try:
            user = cls(**kwargs)
            db_session.add(user)
            db_session.commit()
            return user
        except Exception as e:
            db_session.rollback()
            raise e

    @classmethod
    def get(cls, db_session: Session, user_id):
        """根据ID获取用户"""
        return db_session.query(cls).filter_by(id=user_id).first()

    @classmethod
    def get_all(cls, db_session):
        """获取所有用户"""
        return db_session.query(cls).all()

    @classmethod
    def update(cls, db_session: Session, user_id, **kwargs):
        """更新用户信息"""
        try:
            user = db_session.query(cls).filter_by(id=user_id).first()
            if user:
                for key, value in kwargs.items():
                    setattr(user, key, value)
                db_session.commit()
            return user
        except Exception as e:
            db_session.rollback()
            raise e

    @classmethod
    def delete(cls, db_session: Session, user_id):
        """删除用户"""
        try:
            user = db_session.query(cls).filter_by(id=user_id).first()
            if user:
                db_session.delete(user)
                db_session.commit()
                return True
            return False
        except Exception as e:
            db_session.rollback()
            raise e

    @classmethod
    def get_by_username(cls, db_session: Session, username):
        """根据用户名获取用户"""
        return db_session.query(cls).filter_by(username=username).first()

    @classmethod
    def get_by_email(cls, db_session: Session, email):
        """根据邮箱获取用户"""
        return db_session.query(cls).filter_by(email=email).first()
