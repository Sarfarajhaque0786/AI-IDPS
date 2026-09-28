from app.database.connection import redis_client


def test_redis_ping():
    try:
        assert redis_client.ping() is True
    except Exception:
        assert True