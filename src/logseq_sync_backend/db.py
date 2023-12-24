from datetime import datetime
from sqlalchemy import Column, ForeignKey, create_engine, schema, sql, types
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./db.sqlite"
# SQLALCHEMY_DATABASE_URL = "postgresql://user:password@postgresserver/db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Graphs(Base):
    __tablename__ = "graphs"

    id = Column(types.Integer(), primary_key=True)
    name = Column(types.String(), nullable=False)
    current_txid = Column(types.Integer(), nullable=False)


class GraphSalts(Base):
    __tablename__ = "graph_salts"

    graph_id = Column(ForeignKey("graphs.id", ondelete="CASCADE"), primary_key=True)
    value = Column(types.String(), nullable=False)
    expires_at = Column(types.DateTime(), nullable=False)


class GraphEncryptionKeys(Base):
    __tablename__ = "graph_encryption_keys"

    graph_id = Column(ForeignKey("graphs.id", ondelete="CASCADE"), primary_key=True)
    public_key = Column(types.String(), nullable=False)
    encrypted_private_key = Column(types.String(), nullable=False)


class Transactions(Base):
    __tablename__ = "transactions"

    id = Column(types.Integer(), primary_key=True)
    graph_id = Column(ForeignKey("graphs.id", ondelete="CASCADE"))
    txid = Column(types.Integer(), nullable=False)
    type = Column(types.String(), nullable=False)


class TransactionContent(Base):
    __tablename__ = "transactions_content"

    txn_id = Column(ForeignKey("transactions.id", ondelete="CASCADE"), primary_key=True)
    to_path = Column(types.String(), nullable=False)
    from_path = Column(types.String(), nullable=True)
    checksum = Column(types.String(), nullable=True)


class FilesMetadata(Base):
    __tablename__ = "files_metadata"

    graph_id = Column(ForeignKey("graphs.id", ondelete="CASCADE"), primary_key=True)
    file_id = Column(types.String(), primary_key=True)
    last_modified = Column(types.DateTime(), nullable=False)
    size = Column(types.Integer(), nullable=False)


class FilesVersions(Base):
    __tablename__ = "files_versions"

    file_id = Column(types.String(), primary_key=True)
    version_id = Column(types.String(), primary_key=True)

    create_time = Column(types.DateTime(), nullable=False, default=datetime.utcnow)


def create_database_tables():
    Base.metadata.create_all(bind=engine)


def get_db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


create_database_tables()
