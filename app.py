from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)

API_START_TIME = datetime(2025, 7, 3, 12, 0, 0)
API_EXPIRY_TIME = API_START_TIME + timedelta(days=3)
SECRET_API_KEY = "3dayskeysforujjaiwal"
MAX_REQUESTS = 30

request_counter = {"remaining": MAX_REQUESTS}


def format_time_remaining():
    now = datetime.utcnow()
    remaining = API_EXPIRY_TIME - now
    if remaining.total_seconds() <= 0:
        return "Expired"
    days = remaining.days
    hours, remainder = divmod(remaining.seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    return f"{days} day(s), {hours} hour(s), {minutes} minute(s)"


def load_tokens(server_name):
    if server_name == "IND":
        with open("token_ind.json", "r") as f:
            tokens = json.load(f)
    elif server_name in {"BR", "US", "SAC", "NA"}:
        with open("token_br.json", "r") as f:
            tokens = json.load(f)
    else:
        with open("token_bd.json", "r") as f:
            tokens = json.load(f)
    return tokens


def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')


def create_protobuf_message(user_id, region):
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()


async def send_request(encrypted_uid, token, url):
    edata = bytes.fromhex(encrypted_uid)
    headers = {
        'User-Agent': "Dalvik/2.1.0",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=edata, headers=headers) as response:
            return await response.text()


async def send_multiple_requests(uid, server_name, url):
    region = server_name
    protobuf_message = create_protobuf_message(uid, region)
    encrypted_uid = encrypt_message(protobuf_message)
    tokens = load_tokens(server_name)
    tasks = []
    for i in range(100):
        token = tokens[i % len(tokens)]["token"]
        tasks.append(send_request(encrypted_uid, token, url))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return results


def create_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = int(uid)
    message.garena = 1
    return message.SerializeToString()


def enc(uid):
    return encrypt_message(create_protobuf(uid))


def make_request(encrypt, server_name, token):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    edata = bytes.fromhex(encrypt)
    headers = {
        'User-Agent': "Dalvik/2.1.0",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
    }
    response = requests.post(url, data=edata, headers=headers, verify=False)
    binary = response.content
    items = like_count_pb2.Info()
    items.ParseFromString(binary)
    return items


@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("region", "").upper()
    key = request.args.get("key")

    if not uid or not server_name or not key:
        return jsonify({"error": "UID, region, and key are required"}), 400

    current_time = datetime.utcnow()
    if current_time > API_EXPIRY_TIME or key != SECRET_API_KEY:
        return jsonify({"error": "Invalid API key or expired."}), 403

    if request_counter["remaining"] <= 0:
        return jsonify({"error": "API key usage limit reached. No remaining requests."}), 403

    try:
        def process_request():
            tokens = load_tokens(server_name)
            token = tokens[0]['token']
            encrypted_uid = enc(uid)

            before = make_request(encrypted_uid, server_name, token)
            jsone = MessageToJson(before)
            data_before = json.loads(jsone)
            before_like = int(data_before.get('AccountInfo', {}).get('Likes', 0))

            if server_name == "IND":
                url = "https://client.ind.freefiremobile.com/LikeProfile"
            elif server_name in {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                url = "https://clientbp.ggblueshark.com/LikeProfile"

            asyncio.run(send_multiple_requests(uid, server_name, url))

            after = make_request(encrypted_uid, server_name, token)
            jsone_after = MessageToJson(after)
            data_after = json.loads(jsone_after)
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
            like_given = after_like - before_like
            status = 1 if like_given > 0 else 2

            # Decrement by 1 per call
            request_counter["remaining"] -= 1
            if request_counter["remaining"] < 0:
                request_counter["remaining"] = 0

            result = {
                "KeyExpiresAt": format_time_remaining(),
                "KeyRemainingRequests": f"{request_counter['remaining']}/{MAX_REQUESTS}",
                "LikesGivenByAPI": like_given,
                "LikesbeforeCommand": before_like,
                "LikesafterCommand": after_like,
                "PlayerNickname": player_name,
                "UID": player_uid,
                "status": status
            }
            return result

        result = process_request()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)