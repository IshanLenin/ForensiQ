import redis

# Shared Redis client used across the application.
# decode_responses=True ensures we get Python strings back, not bytes.
redis_client = redis.Redis(host='127.0.0.1', port=6379, db=0, decode_responses=True)
