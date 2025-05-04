from sqlalchemy import create_engine
from sqlalchemy.schema import CreateTable
from database.models import Base  # 替换为实际的模块路径

# 使用PostgreSQL方言（其他数据库需调整）
engine = create_engine("postgresql://user:pass@host/dbname")

# 生成所有表的CREATE语句
tables = Base.metadata.tables.values()
sql_statements = []

for table in tables:
    sql = str(CreateTable(table).compile(engine))
    sql_statements.append(sql)

# 输出到文件或控制台
with open("schema.sql", "w") as f:
    f.write("\n\n".join(sql_statements))
print("SQL已生成到schema.sql")
