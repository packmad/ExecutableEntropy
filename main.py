#!/usr/bin/env python
# coding: utf-8

import logging
import os
import shutil
import tempfile

from flask import Flask
from flask import jsonify
from flask import make_response
from flask import request

from werkzeug.exceptions import BadRequest, InternalServerError
from werkzeug.utils import secure_filename

from exentropy import ElfInfo

# Logging configuration.
logger = logging.getLogger(__name__)
logging.basicConfig(format='[INTERNAL_LOG][%(asctime)s][%(levelname)s][%(funcName)s()] %(message)s',
                    datefmt='%d/%m/%Y %H:%M:%S', level=logging.DEBUG)

app = Flask(__name__)


@app.errorhandler(400)
def bad_request(error):
    logger.error(error)
    return make_response(jsonify({'error': 'Error 400 - Bad Request'}), 400)


@app.errorhandler(500)
def internal_error(error):
    logger.error(error)
    return make_response(jsonify({'error': 'Error 500 - Internal Server Error'}), 500)


@app.route('/', methods=['POST'], strict_slashes=False)
def submit_elf():
    # The POST request must contain a file.
    if 'file' not in request.files:
        raise BadRequest('The body of the request does not contain the file parameter!')

    elf = request.files['file']

    # The POST request must contain a valid file.
    if not elf.filename.strip():
        raise BadRequest('The "file" parameter is empty!')

    filename = secure_filename(elf.filename)

    tmp_dir = tempfile.mkdtemp()

    try:
        tmp_path = os.path.join(tmp_dir, filename)
        elf.save(tmp_path)

        with open(tmp_path, 'rb') as tmp_file:
            elf_info = ElfInfo(tmp_file)
            elf_info.get_infos()

        return make_response(jsonify(elf_info.get_data()), 200)

    except Exception as e:
        raise InternalServerError('Error during the analysis: {0}'.format(e))
    finally:
        shutil.rmtree(tmp_dir)
        logger.debug('"{0}" temporary path deleted'.format(tmp_dir))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
