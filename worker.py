import logging

from rq import Worker

from app.queue import ingest_queue, redis_conn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

if __name__ == "__main__":
    worker = Worker([ingest_queue], connection=redis_conn)
    worker.work()
