# main.py
from flask import Flask, send_file
import os

app = Flask(__name__)

# Get the directory where this script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route('/')
def index():
    return send_file(os.path.join(BASE_DIR, 'index.html'))

@app.route('/styles.css')
def styles():
    return send_file(os.path.join(BASE_DIR, 'styles.css'), mimetype='text/css')

@app.route('/script.js')
def script():
    return send_file(os.path.join(BASE_DIR, 'script.js'), mimetype='application/javascript')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)