from pymongo import MongoClient
from utility import conf


def create_mongo_connection(database_name = conf.mongoconfig.get('database_name')):
	mongo = MongoClient(conf.mongoconfig.get('connection_url'))
	return mongo[database_name]