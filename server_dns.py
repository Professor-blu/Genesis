from flask import Flask, request, jsonify
import json

app = Flask(__name__)

@app.route('/callback', methods=['GET', 'POST'])
def callback():
    client_ip = request.remote_addr
    
    print(f"Received {request.method} request to /callback from {client_ip}")
    
    print("Headers:")
    for header, value in request.headers.items():
        print(f"  {header}: {value}")
    
    if request.args:
        print("Query Parameters:")
        for param, value in request.args.items():
            print(f"  {param}: {value}")
    

    if request.form:
        print("Form Data:")
        for form_key, form_value in request.form.items():
            print(f"  {form_key}: {form_value}")
    
    if request.is_json:
        try:
            json_data = request.get_json()
            print("JSON Payload:")
            print(json.dumps(json_data, indent=4))
        except Exception as e:
            print(f"Error decoding JSON: {e}")
    
    if request.data:
        print("Raw Body Data:")
        print(request.data.decode('utf-8', errors='replace'))

    response = {
        "message": "Callback received",
        "client_ip": client_ip,
        "headers": dict(request.headers),
        "query_params": dict(request.args),
        "form_data": dict(request.form),
        "json_data": request.get_json() if request.is_json else None
    }

    return jsonify(response), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)