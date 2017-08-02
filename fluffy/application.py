import sys
import os
from flask import Flask, render_template
from flasgger import Swagger
from flasgger.utils import swag_from
import logging
import yaml
import logging
import logging.config

from .fluffy import Fluffy

# flask app
app = Flask(__name__)
app.config.from_object('fluffy.default_settings')
app.config.from_envvar('FLUFFY_SETTINGS', silent=True)

if 'FLUFFY_CONFIG_FILE' in os.environ:
    config_file = os.environ['FLUFFY_CONFIG_FILE']
else:
    config_file = '/etc/fluffy/fluffy.yaml'

# set up logging
logging_config = os.path.join(os.path.dirname(config_file), 'logging.yaml')
with open(logging_config, 'r') as stream:
    logging.config.dictConfig(yaml.load(stream))

logger = logging.getLogger(__name__)
if 'FLUFFY_LOGLEVEL' in os.environ:
    for name, logger in logging.Logger.manager.loggerDict.iteritems():
        logger.setLevel(logging.getLevelName(os.environ['FLUFFY_LOGLEVEL']))

fw = Fluffy.load_yaml(config_file)

# autodoc
swagger = Swagger()

from .views.v1 import app as APIv1
app.register_blueprint(APIv1, url_prefix='/v1')

app.config['SWAGGER'] = {
    'version': '0.0.1',
    'title': 'Fluffy API',
    'specs': [
        {
            'version': '0.0.1',
            'title': 'Fluffy API v1',
            'description': 'This is the version 1 of the Fluffy API',
            'endpoint': 'v1_spec',
            'route': '/v1/spec',
            'rule_filter': lambda rule: rule.endpoint.startswith('v1')
        }
    ]
}
swagger.init_app(app)


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')
