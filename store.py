import os
import redis

# set STORAGE_HOST="redis-15795.c13559.us-east-1-mz.ec2.cloud.rlrcp.com"
# os.environ.get('STORAGE_HOST')
# set STORAGE_PSWD="9LzplpsFDcY3QMhDlFygDzQXPnAeJlVZ"
# os.environ.get('STORAGE_PSWD')

POOL = redis.BlockingConnectionPool(host="redis-15795.c13559.us-east-1-mz.ec2.cloud.rlrcp.com",
                                    port=15795,
                                    db=0,
                                    password="9LzplpsFDcY3QMhDlFygDzQXPnAeJlVZ",
                                    max_connections=5,
                                    timeout=0.5)


def get_redis_connection():
    return redis.Redis(connection_pool=POOL, charset='utf-8')


def get(key):
    try:
        rds = get_redis_connection()
        response = rds.get(key)
        return response
    except Exception:
        raise Exception


def cache_get(key):
    try:
        rds = get_redis_connection()
        response = rds.get(key)
        return response
    except Exception:
        return None


def cache_set(key, score, ttl):
    rds = get_redis_connection()
    rds.set(key, score, ex=ttl)


