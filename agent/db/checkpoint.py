import os
from pymongo import MongoClient
from langgraph.checkpoint.mongodb import MongoDBSaver


def make_checkpointer() -> MongoDBSaver:
    uri = os.environ["MONGODB_URI"]
    client = MongoClient(uri)
    db_name = os.environ.get("MONGODB_DB", "cve_agent")
    return MongoDBSaver(client, db_name=db_name)
