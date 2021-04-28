from flask import Flask, jsonify, request, make_response, abort

from flask_restful import Api, Resource
import jwt
import hashlib
import datetime as dt
from datetime import datetime
from functools import wraps
from bson.objectid import ObjectId


from utility.DBConnectivity import create_mongo_connection


app = Flask(__name__)
mongodb = create_mongo_connection()
##############################################################
##############################################################
################## Item Kart #################################
##############################################################
##############################################################

# Create an application for Item Kart
# The application should have the following functionality:
# 1. User login (Authentication)
# 2. List all the items available in the shop as per category (With limits and offsets)
# 3. Add the items to the cart (Authentication required)
# 4. List the items present in the cart (Authentication required)
# 5. Remove and Edit items of the cart (Authentication required)


# You can start writing your code for the above mentioned functionalities from here

app.config['SECRET_KEY'] = 'APITEST'
api = Api(app, prefix='/api/v1')


def verify_password(username, password):
	if not username or not password:
		return False
	
	user_data = mongodb.users.find_one({"$or": [{'name': username}, {"_id": username}]})
	if user_data:
		
		hexdigit = hashlib.sha1(str(password).encode('UTF-8')).hexdigest()

		if user_data.get('password') == hexdigit:
			return True
	
	return False


def token_validate(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = request.args.get('token')

		if not token:
			return abort(jsonify(message='Token is Missing!'))

		try:
			data = jwt.decode(token, app.config['SECRET_KEY'])
			kwargs['user'] = data
			kwargs['user_id'] = data.get('user_id')
		except jwt.ExpiredSignatureError:
			return abort(jsonify(message='Signature expired. Please log in again.'))
		except jwt.InvalidTokenError:
			return abort(jsonify(message='Invalid token. Please log in again.'))
		
		return f(*args, **kwargs)

	return decorated


def token_generator(auth):
	user_data = mongodb.users.find_one({"$or": [{'name': auth.username}, {"_id": auth.username}]})

	expiry = datetime.utcnow() + dt.timedelta(minutes=30)
	token = jwt.encode({'user_name': user_data.get('name'), 'user_id': user_data.get('_id'), 'exp': expiry}, app.config['SECRET_KEY'])

	return jsonify({'token': token.decode('UTF-8')})


@app.route('/login', methods=['GET', 'POST'])
def login():
	auth = request.authorization
	
	# print(mongodb.list_collection_names())
	# print(mongodb.users.count())
	print(mongodb.users.find_one())

	if auth and verify_password(auth.username, auth.password):
		return token_generator(auth)

	return make_response("Couldn't Verify", 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})


class ListItem(Resource):
	def get(self):
		items = mongodb.items
		offset = int(request.args.get('offset') or 0)
		limit = int(request.args.get('limit') or 10)

		items = items.find().sort('_id', 1).skip(offset).limit(limit)

		res_item = [{'item': i} for i in items]

		nxt_url = '/api/v1/item?limit={}&offset={}'.format(limit, offset + limit)
		prev_url = '/api/v1/item?limit={}&offset={}'.format(limit, (offset - limit) if (offset - limit) > 0 else 0)

		return jsonify({'data': res_item, 'nxt_url': nxt_url, 'prev_url': prev_url})


class KartItem(Resource):
	@token_validate
	def get(self, *args, **kwargs):
		user_id = kwargs.get('user_id')

		cond_dict = {
			'item_code': {'$ne': None},
			'user': user_id
		}

		if request.args.get('item'):
			cond_dict['item_code'] = request.args.get('item')

		cart = mongodb.carts.aggregate([{
				'$match': cond_dict
			},
			{
				'$group': {
					'_id': '$item_code',
					'total_qty': {'$sum': '$qty'},
					'cart_id': {
						'$push': {
							'$convert': {
								'input': '$_id',
								'to': 'string'
							}
						}
					}
				}
			},
			{
				'$project': {
					'item_code': '$_id',
					'total_qty': 1,
					'_id': 0,
					'cart_id': 1
				}
			}
		])

		return jsonify(data=list(cart or []))
	

	@token_validate
	def post(self, *args, **kwargs):
		user_id = kwargs.get('user_id')
		self.validate_item()

		qty = int(request.args.get('qty') or 1)
		
		cart = mongodb.carts.insert_one({'user': user_id, 'item_code': self.item_code, 'qty': qty})

		return jsonify(cart_id=str(cart.inserted_id), message="Item Insert inside User Cart")


	@token_validate
	def delete(self, *args, **kwargs):
		user_id = kwargs.get('user_id')
		self.validate_item()

		cart = mongodb.carts.delete_many({'user': user_id, 'item_code': self.item_code})

		return jsonify(message="Item Entry in User Cart is Deleted", count=cart.deleted_count)
	

	@token_validate
	def put(self, *args, **kwargs):
		user_id = kwargs.get('user_id')
		
		cart_id = request.args.get('cart')

		if not cart_id:
			return abort(jsonify(message='Cart ID not Found'))
		
		
		cart = mongodb.carts.find({'$and': [
			{'user': user_id}, 
			{'_id': ObjectId(cart_id)}
		]})
		
		if not cart:
			return abort(jsonify(message='Invalid Cart ID'))
		
		if not request.args.get('item') and request.args.get('qty') is None:
			return abort(jsonify(message='No Object found to update'))

		update_dict = {}
		if request.args.get('item'):
			update_dict['item_code'] = request.args.get('item')
		
		if not request.args.get('qty') is None:
			update_dict['qty'] = int(request.args.get('qty'))
		# print(update_dict)
		
		ch_cart = mongodb.carts.update_one({'_id': ObjectId(cart_id)}, {'$set': update_dict})

		return jsonify(message="Cart Update Successfully")
	

	def validate_item(self):
		self.item_code = request.args.get('item')
		
		item = mongodb.items.find_one({'_id': self.item_code})

		if not item:
			return abort(jsonify(message='Item Code not found'))



api.add_resource(ListItem, '/item')
api.add_resource(KartItem, '/cart')



if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5000, threaded=True)