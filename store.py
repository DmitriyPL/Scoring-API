import redis
import time


from functools import wraps, partial


# set STORAGE_HOST="redis-15795.c13559.us-east-1-mz.ec2.cloud.rlrcp.com"
# os.environ.get('STORAGE_HOST')
# os.environ.get('STORAGE_PSWD')

def attach_wrapper(obj, func=None):
    if func is None:
        return partial(attach_wrapper, obj)
    setattr(obj, func.__name__, func)
    return func


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

        @attach_wrapper(wrapper)
        def set_retry_param(new_tries, new_timeout):
            nonlocal tries, timeout
            tries = new_tries
            timeout = new_timeout

        return wrapper
    return decorate


class RedisConnection:

    def __init__(self,
                 host="redis-15795.c13559.us-east-1-mz.ec2.cloud.rlrcp.com",
                 port=15795,
                 index_db=0,
                 password="***",
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
        rds = self.get_connection()
        response = rds.get(key)
        return response

    @retry(connection_type="like_cache")  # Если не удается достучаться до базы, возвращаем None
    def cache_get(self, key):
        rds = self.get_connection()
        response = rds.get(key)
        return response

    @retry(connection_type="like_cache")  # Если не удается достучаться до базы, возвращаем None
    def cache_set(self, key, score, ttl):
        rds = self.get_connection()
        rds.set(key, score, ex=ttl)


