import redis
import time
import os

from functools import wraps


def retry(tries=3, timeout=0.1, connection_type="like_db"):
    def decorate(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for i in range(tries):
                try:
                    return func(*args, **kwargs)
                except Exception:
                    if i < tries - 1:
                        time.sleep(timeout)
                        continue
                    else:
                        if connection_type == "like_cache":
                            return None
                        else:
                            raise Exception
        return wrapper
    return decorate


class RedisConnection:

    def __init__(self,
                 host="redis-15795.c13559.us-east-1-mz.ec2.cloud.rlrcp.com",
                 port=15795,
                 index_db=0,
                 password=os.environ.get('STORAGE_PSWD'),
                 max_connections=3,
                 timeout=0.5
                 ):
        self.host = host
        self.port = port
        self.index_db = index_db
        self.password = password
        self.max_connections = max_connections
        self.timeout = timeout

    def get_connection(self):
        pool = redis.BlockingConnectionPool(host=self.host,
                                            port=self.port,
                                            db=self.index_db,
                                            password=self.password,
                                            max_connections=self.max_connections,
                                            timeout=self.timeout
                                            )
        return redis.Redis(connection_pool=pool, charset='utf-8')

    @retry(connection_type="like_db")  # Если не удается достучаться до базы, падаем с ошибкой
    def get(self, key):
        return self.common_get(key)

    @retry(connection_type="like_cache")  # Если не удается достучаться до базы, возвращаем None
    def cache_get(self, key):
        return self.common_get(key)

    @retry(connection_type="like_cache")
    def cache_set(self, key, score, ttl):
        rds = self.get_connection()
        if type(score) is list:
            rds.lpush(key, *score)
        else:
            rds.set(key, score, ex=ttl)

    def common_get(self, key):
        rds = self.get_connection()
        if rds.type(key) == b'list':
            response = [item.decode() for item in rds.lrange(key, 0, -1)]
        else:
            response = rds.get(key)
        return response


