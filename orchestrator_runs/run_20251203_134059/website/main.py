from flask import Flask, render_template, send_from_directory

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/styles.css')
def styles():
    return send_from_directory('static', 'styles.css')

@app.route('/script.js')
def script():
    return send_from_directory('static', 'script.js')

@app.route('/pizza1.jpg')
def pizza1():
    return send_from_directory('static', 'pizza1.jpg')

@app.route('/pizza2.jpg')
def pizza2():
    return send_from_directory('static', 'pizza2.jpg')

@app.route('/pizza3.jpg')
def pizza3():
    return send_from_directory('static', 'pizza3.jpg')

if __name__ == '__main__':
    app.run(port=5000, debug=True)