from flask import Flask, send_file

app=Flask(__name__)

@app.route('/')
def index():
	return 'Hello World'
@app.route('/return-file')
def return_file():
	return send_file("/home/pi/webapp/test.pcap",attachment_filename="test.pcap")
def file_downloads():
	return 'pcap downloads'

if __name__ == '__main__':
	app.run(debug=True,host='0.0.0.0',port=8000)