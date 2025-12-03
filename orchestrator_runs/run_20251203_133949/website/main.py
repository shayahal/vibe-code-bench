# main.py
from flask import Flask, render_template, send_from_directory

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/styles.css')
def styles():
    return send_from_directory('.', 'styles.css')

@app.route('/script.js')
def script():
    return send_from_directory('.', 'script.js')

@app.route('/pizza1.jpg')
def pizza1():
    return send_from_directory('.', 'pizza1.jpg')

@app.route('/pizza2.jpg')
def pizza2():
    return send_from_directory('.', 'pizza2.jpg')

@app.route('/pizza3.jpg')
def pizza3():
    return send_from_directory('.', 'pizza3.jpg')

@app.route('/hero-bg.jpg')
def hero_bg():
    return send_from_directory('.', 'hero-bg.jpg')

if __name__ == '__main__':
    app.run(port=5000, debug=False)