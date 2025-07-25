from flask import Flask, request, jsonify
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

# UID and password database for JWT tokens
UID_PASSWORD_DB = {
    "3934169005": "A2CA47ADC10E47A5D9377C3A01386832B23AA6A045AB41C9536010D7538ADC48"
}

async def get_fresh_token(uid):
    password = UID_PASSWORD_DB.get(uid)
    if not password:
        app.logger.error(f"No password found for UID: {uid}")
        return None

    try:
        url = f"https://project-jwt-token-ujjaiwal.vercel.app/token?uid={uid}&password={password}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "live":
                        app.logger.info(f"Token fetched for UID {uid}")
                        return data.get("token")
                    else:
                        app.logger.error(f"Token status not live for UID: {uid}")
                else:
                    app.logger.error(f"Failed to get token for UID: {uid}, Status: {response.status}")
    except Exception as e:
        app.logger.error(f"Error getting token: {e}")
    return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Encryption error: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Protobuf creation error: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'User-Agent': "Dalvik/2.1.0",
            'Accept-Encoding': "gzip",
            'Connection': "Keep-Alive",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB49"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Like POST failed: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"send_request error: {e}")
        return None

async def send_multiple_requests(uid, region, url):
    try:
        proto_data = create_protobuf_message(uid, region)
        if not proto_data:
            return None

        encrypted_uid = encrypt_message(proto_data)
        if not encrypted_uid:
            return None

        tasks = []
        for i in range(100):
            token_uid = list(UID_PASSWORD_DB.keys())[i % len(UID_PASSWORD_DB)]
            token = await get_fresh_token(token_uid)
            if token:
                tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"send_multiple_requests error: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"UID proto error: {e}")
        return None

def enc(uid):
    data = create_protobuf(uid)
    return encrypt_message(data) if data else None

async def make_request(encrypted, region):
    try:
        if region == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif region in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

        token_uid = list(UID_PASSWORD_DB.keys())[0]
        token = await get_fresh_token(token_uid)
        if not token:
            return None

        edata = bytes.fromhex(encrypted)
        headers = {
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'User-Agent': "Dalvik/2.1.0",
            'Accept-Encoding': "gzip",
            'Connection': "Keep-Alive",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB49"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"make_request failed: {response.status}")
                    return None
                hex_data = (await response.read()).hex()
                binary = bytes.fromhex(hex_data)
                decoded = decode_protobuf(binary)
                return decoded
    except Exception as e:
        app.logger.error(f"make_request error: {e}")
        return None

def decode_protobuf(binary):
    try:
        obj = like_count_pb2.Info()
        obj.ParseFromString(binary)
        return obj
    except DecodeError as e:
        app.logger.error(f"Protobuf DecodeError: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Protobuf decode error: {e}")
        return None

@app.route('/like', methods=['GET'])
async def handle_requests():
    uid = request.args.get("uid")
    region = request.args.get("region", "").upper()
    key = request.args.get("key")

    if not uid or not region or not key:
        return jsonify({"error": "UID, region, and key are required"}), 400

    if key != "permanentskeysforujjaiwal":
        return jsonify({"error": "Invalid API key"}), 403

    try:
        encrypted_uid = enc(uid)
        if not encrypted_uid:
            raise Exception("Encryption failed")

        before = await make_request(encrypted_uid, region)
        if not before:
            raise Exception("Failed to retrieve initial player info")

        before_json = MessageToJson(before)
        before_data = json.loads(before_json)
        before_like = int(before_data.get('AccountInfo', {}).get('Likes', 0))

        app.logger.info(f"Likes before: {before_like}")

        like_url = (
            "https://client.ind.freefiremobile.com/LikeProfile" if region == "IND"
            else "https://client.us.freefiremobile.com/LikeProfile" if region in {"BR", "US", "SAC", "NA"}
            else "https://clientbp.ggblueshark.com/LikeProfile"
        )

        await send_multiple_requests(uid, region, like_url)

        after = await make_request(encrypted_uid, region)
        if not after:
            raise Exception("Failed to retrieve player info after likes")

        after_json = MessageToJson(after)
        after_data = json.loads(after_json)
        after_like = int(after_data.get('AccountInfo', {}).get('Likes', 0))
        nickname = after_data.get('AccountInfo', {}).get('PlayerNickname', '')
        final_uid = after_data.get('AccountInfo', {}).get('UID', '')

        like_given = after_like - before_like
        status = 1 if like_given > 0 else 2

        return jsonify({
            "LikesGivenByAPI": like_given,
            "LikesbeforeCommand": before_like,
            "LikesafterCommand": after_like,
            "PlayerNickname": nickname,
            "UID": final_uid,
            "status": status
        })
    except Exception as e:
        app.logger.error(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)