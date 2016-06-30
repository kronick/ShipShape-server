import json
import os
import datetime

from functools import wraps
from flask import Flask, jsonify, request, render_template, send_from_directory, g, url_for, Response
from werkzeug.security import generate_password_hash, check_password_hash

from pymongo import MongoClient
import bson.errors
from bson.objectid import ObjectId
from bson.json_util import dumps as bson2json

app = Flask(__name__)

CONFIG = {
    "db_name": "ShipShape"
}

# DATABASE FUNCTIONS
# --------------------------------------------------------------------------
def get_mongoclient():
    mongoclient = getattr(g, '_mongoclient', None)
    if mongoclient is None:
        mongoclient = g._mongoclient = MongoClient()
    return mongoclient
    
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = get_mongoclient()[CONFIG["db_name"]]

    return db

@app.teardown_appcontext
def close_connection(exception):
    mongoclient = getattr(g, '_mongoclient', None)
    if mongoclient is not None:
        mongoclient.close()
        
# AUTHORIZATION DECORATORS
# ---------------------------------------------------------------------------
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth:
            return Response( 'Could not verify your access level for that URL.\n'
                                    'You have to login with proper credentials', 401,
                                    {'WWW-Authenticate': 'Basic realm="Login Required"'})
        elif not authenticate_sailor(auth.username, auth.password):
            return jsonify({"error": "Wrong username or password."}), 403
            
        db = get_db()                            
        g.authenticated_sailor = db.sailors.find_one({'username': auth.username})                                    
        return f(*args, **kwargs)
    return decorated    

def optional_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not authenticate_sailor(auth.username, auth.password):
            g.authenticated_sailor = None
        else:        
            db = get_db()               
            g.authenticated_sailor = db.sailors.find_one({'username': auth.username})                                    
            
        return f(*args, **kwargs)
    return decorated        



@app.route('/')
@optional_auth
def get_index():
    name = ""
    if g.authenticated_sailor:
        name = ", {}".format(g.authenticated_sailor.get(u"username") or "UNKNOWN")
    return "WELCOME ABOARD{}".format(name)


@app.route('/api/v0.1/reindex')
def rebuild_database_index():
    """ Rebuild the indices on each collection """
    db = get_db()
    
    return "NOT YET IMPLEMENTED", 501

    
# "Sailor" CRUD endpoints
# --------------------------------------------------------------------------
@app.route('/api/v0.1/checkauth/')
@requires_auth
def check_authorization():
    return jsonify({"status": "Welcome aboard, {}".format(g.authenticated_sailor.get(u"username" or "UNKNOWN"))}), 200

@app.route('/api/v0.1/sailors/<sailor_id>/', methods=["GET"])
@optional_auth
def get_sailor(sailor_id):
    # Find in sailors where _id = sailor_id
    db = get_db()
    sailor = db.sailors.find_one({'_id': ObjectId(str(sailor_id))})
    
    if sailor is None:
        return "No sailors found!", 404
    
    # Clean up values that will be returned
    sailor["_id"] = str(sailor["_id"])
    del sailor["password"]  # don't include password hash
    return jsonify(sailor)

@app.route('/api/v0.1/sailors/<sailor_id>/', methods=["DELETE"])
@requires_auth
def delete_sailor(sailor_id):
    return "Delete sailor {} - not yet implemented".format(sailor_id), 501
    
@app.route('/api/v0.1/sailors/<sailor_id>/', methods=["PATCH"])
@requires_auth
def update_sailor(sailor_id):
    return "Update sailor {} - not yet implemented".format(sailor_id), 501

@app.route('/api/v0.1/sailors/', methods=["POST"])
def create_sailor():
    db = get_db()
    
    request_data = request.get_json()
    # profile, password, realName, username, email

    # Validate input - make sure username and password are OK
    if not request_data.get("username") or not request_data.get("password"):
        return jsonify({"error": "Must include username and password in request."}), 400
    if len(request_data["username"]) < 3:
        return jsonify({"error": "Username must be greater than 2 characters long."}), 400
    if len(request_data["password"]) < 8:
        return jsonify({"error": "Password must be 8 or more characters long."}), 400        
    if len(request_data["password"]) >= 1024:
        return jsonify({"error": "Password must be less than 1024 characters-- what do you think you're doing???"}), 400                
    if db.sailors.find_one({'username': request_data["username"]}):
        return jsonify({"error": "That username already exists!"}), 409
    
    # TODO: Check lengths on all fields to prevent DDoS
    
    # Hash the password (with embedded salt) before storing it
    request_data["password"] = generate_password_hash(request_data["password"])
    
    # Insert the request into the database
    new_sailor_id = db.sailors.insert_one(request_data).inserted_id

    sailor_id = str(new_sailor_id)
    url = url_for("get_sailor", sailor_id=sailor_id)

    return jsonify( {"sailor_id": sailor_id, "url": url, "status": "Success!"} ), 200

    
@app.route('/api/v0.1/sailors/<sailor_id>/paths/', methods=["GET"])
@optional_auth
def get_sailor_paths(sailor_id):
    """ Return all paths owned by the given sailor """
    return "Get paths for sailor {} - not yet implemented".format(sailor_id), 501

@app.route('/api/v0.1/sailors/<int:sailor_id>/vessels/', methods=["GET"])
@optional_auth
def get_sailor_vessels(sailor_id):
    """ Return all vessels owned by the given sailor """
    return "Get vessels for sailor {} - not yet implemented".format(sailor_id), 501

def authenticate_sailor(username, password):
    """ Check provided username and password against the name and hashed password in the database """
    db = get_db()
    sailor = db.sailors.find_one({'username': username})
    if not sailor:
        return False
    
    if check_password_hash(sailor.get("password") or "", password):
        return True
    
    return False


# "Path" CRUD endpoints
# --------------------------------------------------------------------------
@app.route('/api/v0.1/paths/<path_id>/', methods=["GET"], defaults={"include_points": True, "include_geojson": False})
@app.route('/api/v0.1/paths/<path_id>/all', methods=["GET"], defaults={"include_points": True, "include_geojson": True})
@app.route('/api/v0.1/paths/<path_id>/metadata', methods=["GET"], defaults={"include_points": False, "include_geojson": False})
@app.route('/api/v0.1/paths/<path_id>/geojson', methods=["GET"], defaults={"include_points": False, "include_geojson": True})
@optional_auth
def get_path(path_id, include_points, include_geojson):
    # Find in paths where _id = path_id
    db = get_db()
    filter = {}
    if not include_points:
        filter["points"] = 0
    if not include_geojson:
        filter["shape"] = 0
        
    try:
        path = db.paths.find_one({'_id': ObjectId(str(path_id))}, None if filter == {} else filter)
    except bson.errors.InvalidId:
        return "No path found!", 404
    
    if path is None:
        return "No path found!", 404
    
    # Clean up values that will be returned
    path["_id"] = str(path["_id"])
    if path.has_key("creator_id"):
        path["creator_id"] = str(path["creator_id"])
        
    return jsonify(path)

@app.route('/api/v0.1/paths/<path_id>/', methods=["DELETE"])
@requires_auth
def delete_path(path_id):
    return "Delete path {} - not yet implemented".format(path_id), 501
    
@app.route('/api/v0.1/paths/<path_id>/', methods=["PATCH"])
@requires_auth
def update_path(path_id):
    return "Update path {} - not yet implemented".format(path_id), 501

@app.route('/api/v0.1/paths/', methods=["POST"])
@requires_auth
def create_path():
    request_data = request.get_json()
        
    # Validate input
    if not request_data.get("points"):
        return "No points specified!", 504
    
    # Create a new geojson object and populate it with coordinates
    geojson_shape = { "type": "LineString", "coordinates": [] }
    for point in request_data["points"]:
        geojson_shape["coordinates"].append([point["longitude"],point["latitude"]])
    
    request_data["shape"] = geojson_shape
    
    # Store creator ID from the requesting sailor in the DB
    request_data["creator_id"] = g.authenticated_sailor.get("_id")
        
        
    # Insert the request into the database
    db = get_db()
    new_path_id = db.paths.insert_one(request_data).inserted_id
    
    path_id = str(new_path_id)
    url = url_for("get_path", path_id=path_id)

    return jsonify( {"path_id": path_id, "url": url, "status": "Success!"} ), 200
    
# "Path" search endpoints
# --------------------------------------------------------------------------
@app.route('/api/v0.1/paths/in/<lng1>,<lat1>,<lng2>,<lat2>,<lng3>,<lat3>,<lng4>,<lat4>', methods=["GET"])
def get_paths_in_quad(lng1,lat1,lng2,lat2,lng3,lat3,lng4,lat4):
    """ Search for all paths that intersect with the given lat/long quad """
    # Create GeoJSON-ready version of the viewport quad
    quad = {"type": "Polygon", "coordinates": [[ [lng1,lat1], [lng2,lat2], [lng3,lat3], [lng4,lat4], [lng1,lat1] ]]}
    
    result = []
    for path in db.paths.find({"shape": {"$geoIntersects": {"$geometry": quad} } }):
        path["_id"] = str(path["_id"])
        result.append(path)
        
    return jsonify({"paths": result})

@app.route('/api/v0.1/paths/near/<longitude>,<latitude>', methods=["GET"])
def get_paths_near(longitude, latitude):
    """ Search for all paths near a given point """
    return "Paths near point search ({} , {})- not yet implemented".format(longitude, latitude), 501


# "Vessel" CRUD endpoints
# --------------------------------------------------------------------------
@app.route('/api/v0.1/vessels/<id>/', methods=["GET"])
@optional_auth
def get_vessel(vessel_id):
    # Find inv vessels where _id = vessel_id
    db = get_db()
    vessel = db.vessels.find_one({'_id': ObjectId(str(vessel_id))})
    
    if vessel is None:
        return "No vessel found!", 404
    
    # Clean up values that will be returned
    vessel["_id"] = str(vessel["_id"])
    return jsonify(vessel)

@app.route('/api/v0.1/vessels/<id>/', methods=["DELETE"])
@requires_auth
def delete_vessel(vessel_id):
    return "Delete vessel {} - not yet implemented".format(vessel_id), 501
    
@app.route('/api/v0.1/vessels/<id>/', methods=["PATCH"])
@requires_auth
def update_vessel(vessel_id):
    return "Update vessel {} - not yet implemented".format(vessel_id), 501

@app.route('/api/v0.1/vessels/', methods=["POST"])
@requires_auth
def create_vessel():
    return "Create new vessel - not yet implemented", 501

app.debug = True    
if __name__ == '__main__':
    
    app.run()