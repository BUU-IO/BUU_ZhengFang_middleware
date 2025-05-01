from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.pool import QueuePool
import threading
import contextlib

# 数据库配置
DATABASE_URI = "postgresql+psycopg2://user:password@localhost/mydatabase"
POOL_SIZE = 5
MAX_OVERFLOW = 10
POOL_RECYCLE = 3600

# 创建数据库引擎
engine = create_engine(
    DATABASE_URI,
    poolclass=QueuePool,
    pool_size=POOL_SIZE,
    max_overflow=MAX_OVERFLOW,
    pool_recycle=POOL_RECYCLE,
    echo=False,  # 设置为True可显示SQL日志
)

# 创建线程安全的Session工厂
SessionFactory = sessionmaker(bind=engine)
Session = scoped_session(SessionFactory)

# 声明模型基类
Base = declarative_base()


# 上下文管理器用于自动会话管理
@contextlib.contextmanager
def session_scope():
    """提供事务范围的上下文管理器"""
    session = Session()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        raise
    finally:
        session.close()


def init_db():
    """初始化数据库表结构"""
    Base.metadata.create_all(bind=engine)


def shutdown_db():
    """关闭数据库连接池"""
    engine.dispose()


# 注册线程结束时的清理钩子
threading._register_atexit(shutdown_db)
