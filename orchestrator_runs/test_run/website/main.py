from flask import Flask, send_file

app = Flask(__name__)

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/styles.css')
def styles():
    return send_file('styles.css')

@app.route('/script.js')
def script():
    return send_file('script.js')

if __name__ == '__main__':
    app.run(port=5003, debug=False)
