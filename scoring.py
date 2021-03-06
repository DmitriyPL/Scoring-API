import hashlib


TTL = 60 * 60  # cache for 60 minutes


def get_score(store, phone=None, email=None, birthday=None, gender=None, first_name=None, last_name=None):
    key_parts = [
        first_name if first_name is not None else "",
        last_name if last_name is not None else "",
        str(phone) if phone is not None else "",
        email if email is not None else "",
        birthday if birthday is not None else "",
        str(gender) if gender is not None else ""
    ]
    key = "uid:" + hashlib.md5(("".join(key_parts)).encode()).hexdigest()
    # try get from cache,
    # fallback to heavy calculation in case of cache miss
    score = store.cache_get(key) or 0
    if score:
        return float(score.decode('utf-8'))
    if phone:
        score += 1.5
    if email:
        score += 1.5
    if birthday and gender:
        score += 1.5
    if first_name and last_name:
        score += 0.5
    store.cache_set(key, score, TTL)
    return score


def get_interests(store, cid):
    return store.get("i:{}".format(cid))
