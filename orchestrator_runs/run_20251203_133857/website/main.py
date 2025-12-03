# main.py
from flask import Flask, render_template, send_file

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/styles.css')
def styles():
    return send_file('styles.css')

@app.route('/script.js')
def script():
    return send_file('script.js')

if __name__ == '__main__':
    app.run(port=5000, debug=True)