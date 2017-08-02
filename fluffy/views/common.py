from flask import make_response, jsonify
from flask_api import status
from functools import wraps

from ..application import fw


def session_exists(f):
    @wraps(f)
    def decorated_function(session_name, **kwargs):
        if not fw.sessions.exists(session_name):
            return make_response(jsonify(message='Session not found'), status.HTTP_404_NOT_FOUND)
        return f(session_name, **kwargs)
    return decorated_function
