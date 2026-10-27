from collections.abc import Generator

from sqlalchemy.orm import Session

from sentineltrace.storage.db import get_session_factory


def get_session() -> Generator[Session, None, None]:
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
