from flask import Flask, request, jsonify
import sys
import jwt
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import RemoveFriend_Req_pb2
from byte import Encrypt_ID, encrypt_api
import binascii
import data_pb2
import uid_generator_pb2
from datetime import datetime
import json
import time
import urllib3
import warnings

# -----------------------------
# Security Warnings Disable
# -----------------------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=UserWarning, message="Unverified HTTPS request")

app = Flask(__name__)

# -----------------------------
# AES Configuration
# -----------------------------
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def encrypt_message(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data_bytes, AES.block_size))

def encrypt_message_hex(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(pad(data_bytes, AES.block_size))
    return binascii.hexlify(encrypted).decode('utf-8')

# -----------------------------
# Region-based URL Configuration
# -----------------------------
def get_base_url(server_name):
    server_name = server_name.upper()
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com/"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/"
    else:
        return "https://clientbp.ggblueshark.com/"

def get_server_from_token(token):
    """Extract server region from JWT token"""
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        lock_region = decoded.get("lock_region", "IND")
        return lock_region.upper()
    except:
        return "IND"

# -----------------------------
# JWT Token Generation via External API (3 Methods)
# -----------------------------

def get_jwt_from_eat_token(eat_token):
    """Get JWT using external eat_to_jwt API"""
    try:
        url = f"https://jwt-system-ff.vercel.app/eat_to_jwt?eat_token={eat_token}"
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            return None, f"API error: {response.status_code}"
        
        data = response.json()
        
        if not data.get('success', False):
            return None, data.get('message', 'Unknown error')
        
        jwt_token = data.get('jwt_token')
        if not jwt_token:
            return None, "JWT token not found in response"
        
        return jwt_token, None
        
    except Exception as e:
        return None, f"Request failed: {str(e)}"

def get_jwt_from_access_token(access_token):
    """Get JWT using external access_to_jwt API"""
    try:
        url = f"https://jwt-system-ff.vercel.app/access_to_jwt?access_token={access_token}"
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            return None, f"API error: {response.status_code}"
        
        data = response.json()
        
        if not data.get('success', False):
            return None, data.get('message', 'Unknown error')
        
        jwt_token = data.get('jwt_token')
        if not jwt_token:
            return None, "JWT token not found in response"
        
        return jwt_token, None
        
    except Exception as e:
        return None, f"Request failed: {str(e)}"

def get_jwt_from_uid_password(uid, password):
    """Get JWT using external guest_to_jwt API"""
    try:
        url = f"https://jwt-system-ff.vercel.app/guest_to_jwt?uid={uid}&password={password}"
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            return None, f"API error: {response.status_code}"
        
        data = response.json()
        
        if not data.get('success', False):
            return None, data.get('message', 'Unknown error')
        
        jwt_token = data.get('jwt_token')
        if not jwt_token:
            return None, "JWT token not found in response"
        
        return jwt_token, None
        
    except Exception as e:
        return None, f"Request failed: {str(e)}"

def get_token_common(uid=None, password=None, access_token=None, eat_token=None):
    """Common function to get token from 3 different methods"""
    token = None
    error = None
    
    if eat_token:
        token, error = get_jwt_from_eat_token(eat_token)
        if error:
            return None, error
    elif access_token:
        token, error = get_jwt_from_access_token(access_token)
        if error:
            return None, error
    elif uid and password:
        token, error = get_jwt_from_uid_password(uid, password)
        if error:
            return None, error
    else:
        return None, "Missing authentication (eat_token/access_token/uid+password)"
    
    return token, None

# -----------------------------
# Retry Decorator
# -----------------------------
def retry_operation(max_retries=10, delay=1):
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    result = func(*args, **kwargs)
                    if result and result.get('status') in ['success', 'failed']:
                        return result
                    print(f"Attempt {attempt + 1}/{max_retries} failed, retrying...")
                except Exception as e:
                    last_exception = e
                    print(f"Attempt {attempt + 1}/{max_retries} failed with error: {str(e)}")
                
                if attempt < max_retries - 1:
                    time.sleep(delay)
            
            if last_exception:
                return {
                    "status": "error",
                    "message": f"All {max_retries} attempts failed",
                    "error": str(last_exception)
                }
            return {
                "status": "error", 
                "message": f"All {max_retries} attempts failed"
            }
        return wrapper
    return decorator

# -----------------------------
# Player Info Functions
# -----------------------------
def create_info_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = int(uid)
    message.garena = 1
    return message.SerializeToString()

def get_player_info(target_uid, token, server_name=None):
    """Get detailed player information"""
    try:
        if not server_name:
            server_name = get_server_from_token(token)
            
        protobuf_data = create_info_protobuf(target_uid)
        encrypted_data = encrypt_message_hex(protobuf_data)
        endpoint = get_base_url(server_name) + "GetPlayerPersonalShow"

        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB54"
        }

        response = requests.post(endpoint, data=bytes.fromhex(encrypted_data), headers=headers, verify=False)
        
        if response.status_code != 200:
            return None

        hex_response = response.content.hex()
        binary = bytes.fromhex(hex_response)
        
        info = data_pb2.AccountPersonalShowInfo()
        info.ParseFromString(binary)
        
        return info
    except Exception as e:
        print(f"Error getting player info: {e}")
        return None

def extract_player_info(info_data):
    """Extract player information from protobuf response"""
    if not info_data:
        return None

    basic_info = info_data.basic_info
    
    friends_count = 0
    try:
        if hasattr(info_data, 'friends'):
            friends_count = len(info_data.friends)
        elif hasattr(info_data, 'friend_list'):
            friends_count = len(info_data.friend_list)
        elif hasattr(info_data, 'social_info') and hasattr(info_data.social_info, 'friend_count'):
            friends_count = info_data.social_info.friend_count
    except:
        friends_count = 0
    
    return {
        'uid': basic_info.account_id,
        'nickname': basic_info.nickname,
        'level': basic_info.level,
        'region': basic_info.region,
        'likes': basic_info.liked,
        'release_version': basic_info.release_version,
        'friends_count': friends_count
    }

# -----------------------------
# Authentication Helper
# -----------------------------
def decode_author_uid(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded.get("account_id") or decoded.get("sub")
    except:
        return None

# -----------------------------
# Get Friends List Function
# -----------------------------
def get_friends_list(target_uid, token, server_name=None):
    """Get friends list using GetPlayerSocialNetwork endpoint"""
    try:
        if not server_name:
            server_name = get_server_from_token(token)
            
        msg = uid_generator_pb2.uid_generator()
        msg.saturn_ = int(target_uid)
        msg.garena = 1
        
        protobuf_data = msg.SerializeToString()
        encrypted_data = encrypt_message_hex(protobuf_data)
        
        endpoint = get_base_url(server_name) + "GetPlayerSocialNetwork"

        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB54"
        }

        response = requests.post(endpoint, data=bytes.fromhex(encrypted_data), headers=headers, verify=False)
        
        if response.status_code != 200:
            return [], 0

        try:
            if hasattr(data_pb2, 'SocialNetwork') or hasattr(data_pb2, 'PlayerSocialNetwork'):
                social_info = data_pb2.SocialNetwork() if hasattr(data_pb2, 'SocialNetwork') else data_pb2.PlayerSocialNetwork()
                hex_response = response.content.hex()
                binary = bytes.fromhex(hex_response)
                social_info.ParseFromString(binary)
                
                friends_list = []
                friends_count = 0
                
                if hasattr(social_info, 'friends'):
                    friends_count = len(social_info.friends)
                    for friend in social_info.friends:
                        name = getattr(friend, 'nickname', None) or getattr(friend, 'name', 'Unknown')
                        friends_list.append(name)
                elif hasattr(social_info, 'friend_list'):
                    friends_count = len(social_info.friend_list)
                    for friend in social_info.friend_list:
                        name = getattr(friend, 'nickname', None) or getattr(friend, 'name', 'Unknown')
                        friends_list.append(name)
                
                return friends_list, friends_count
            else:
                return [], 0
                
        except Exception as e:
            print(f"Error parsing friends list: {e}")
            return [], 0

    except Exception as e:
        print(f"Error getting friends list: {e}")
        return [], 0

# -----------------------------
# Friend Management Functions
# -----------------------------

@retry_operation(max_retries=10, delay=1)
def remove_friend_with_retry(author_uid, target_uid, token, server_name=None):
    """Remove friend with retry mechanism"""
    try:
        if not server_name:
            server_name = get_server_from_token(token)
            
        player_info = get_player_info(target_uid, token, server_name)
        friends_names, friends_count = get_friends_list(target_uid, token, server_name)
        
        msg = RemoveFriend_Req_pb2.RemoveFriend()
        msg.AuthorUid = int(author_uid)
        msg.TargetUid = int(target_uid)
        encrypted_bytes = encrypt_message(msg.SerializeToString())

        url = get_base_url(server_name) + "RemoveFriend"
        headers = {
            'Authorization': f"Bearer {token}",
            'User-Agent': "Dalvik/2.1.0 (Linux; Android 9)",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB54"
        }

        res = requests.post(url, data=encrypted_bytes, headers=headers, verify=False)
        
        player_data = None
        if player_info:
            player_data = extract_player_info(player_info)
        
        if res.status_code == 200:
            status = "success"
        else:
            status = "failed"
            raise Exception(f"HTTP {res.status_code}: {res.text}")
        
        response_data = {
            "remover_uid": author_uid,
            "nickname": player_data.get('nickname') if player_data else "Unknown",
            "removed_uid": target_uid,
            "level": player_data.get('level') if player_data else 0,
            "likes": player_data.get('likes') if player_data else 0,
            "friends_count": friends_count if friends_count else player_data.get('friends_count', 0),
            "friends_names": friends_names if friends_names else [],
            "region": player_data.get('region') if player_data else "Unknown",
            "release_version": player_data.get('release_version') if player_data else "Unknown",
            "status": status,
            "jwt_token": token,
            "owner_tg": "@SKY_DROGON",
            "channel_tg": "@DRAGON_AARMY_LEGEND_1",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return response_data

    except Exception as e:
        print(f"Remove friend error: {e}")
        raise e

@retry_operation(max_retries=10, delay=1)
def send_friend_request_with_retry(author_uid, target_uid, token, server_name=None):
    """Send friend request with retry mechanism"""
    try:
        if not server_name:
            server_name = get_server_from_token(token)
            
        player_info = get_player_info(target_uid, token, server_name)
        friends_names, friends_count = get_friends_list(target_uid, token, server_name)
        
        encrypted_id = Encrypt_ID(target_uid)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)

        url = get_base_url(server_name) + "RequestAddingFriend"
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB54",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)"
        }

        r = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), verify=False)
        
        player_data = None
        if player_info:
            player_data = extract_player_info(player_info)
        
        if r.status_code == 200:
            status = "success"
        else:
            status = "failed"
            raise Exception(f"HTTP {r.status_code}: {r.text}")
        
        response_data = {
            "your_uid": author_uid,
            "owner_uid": "8809806596",
            "nickname": player_data.get('nickname') if player_data else "Unknown",
            "friend_uid": target_uid,
            "level": player_data.get('level') if player_data else 0,
            "likes": player_data.get('likes') if player_data else 0,
            "friends_count": friends_count if friends_count else player_data.get('friends_count', 0),
            "friends_names": friends_names if friends_names else [],
            "region": player_data.get('region') if player_data else "Unknown",
            "release_version": player_data.get('release_version') if player_data else "Unknown",
            "status": status,
            "jwt_token": token,
            "owner_tg": "@SKY_DROGON",
            "channel_tg": "@DRAGON_AARMY_LEGEND_1",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return response_data
        
    except Exception as e:
        print(f"Add friend error: {e}")
        raise e

# -----------------------------
# Routes
# -----------------------------

@app.route('/')
def home():
    # Get the base URL dynamically
    host = request.host_url.rstrip('/')
    
    html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>🔥 FreeFire API - Friend Manager</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
            min-height: 100vh;
            padding: 30px 20px;
            color: #fff;
        }
        
        .container {
            max-width: 1100px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.06);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-radius: 40px;
            padding: 35px 30px;
            border: 1px solid rgba(255, 255, 255, 0.08);
            box-shadow: 0 30px 60px rgba(0,0,0,0.6);
        }
        
        .header {
            text-align: center;
            margin-bottom: 35px;
        }
        
        .header h1 {
            font-size: 2.8rem;
            font-weight: 800;
            background: linear-gradient(90deg, #f7971e, #ffd200, #f7971e);
            background-size: 200% auto;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: shimmer 3s linear infinite;
        }
        
        @keyframes shimmer {
            0% { background-position: 0% center; }
            100% { background-position: 200% center; }
        }
        
        .header p {
            color: #aaa;
            font-size: 1.1rem;
            margin-top: 8px;
        }
        
        .badge {
            display: inline-block;
            background: rgba(255, 215, 0, 0.15);
            color: #ffd700;
            padding: 5px 18px;
            border-radius: 30px;
            font-size: 0.85rem;
            border: 1px solid rgba(255, 215, 0, 0.2);
            margin-top: 10px;
        }
        
        .base-url-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 18px 22px;
            margin-bottom: 30px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
            border: 1px solid rgba(255,255,255,0.06);
        }
        
        .base-url-card .label {
            color: #888;
            font-size: 0.9rem;
        }
        
        .base-url-card .url {
            color: #4fc3f7;
            font-size: 1.1rem;
            font-weight: 600;
            word-break: break-all;
        }
        
        .copy-btn {
            background: rgba(79, 195, 247, 0.15);
            border: 1px solid rgba(79, 195, 247, 0.3);
            color: #4fc3f7;
            padding: 8px 18px;
            border-radius: 30px;
            cursor: pointer;
            font-size: 0.85rem;
            transition: all 0.3s;
        }
        
        .copy-btn:hover {
            background: rgba(79, 195, 247, 0.25);
            transform: scale(1.02);
        }
        
        .endpoint-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 35px;
        }
        
        .endpoint-card {
            background: rgba(255, 255, 255, 0.04);
            border-radius: 20px;
            padding: 22px 24px;
            border: 1px solid rgba(255, 255, 255, 0.06);
            transition: all 0.3s ease;
        }
        
        .endpoint-card:hover {
            transform: translateY(-4px);
            border-color: rgba(255, 215, 0, 0.2);
            box-shadow: 0 12px 30px rgba(0,0,0,0.3);
        }
        
        .endpoint-card .method {
            display: inline-block;
            padding: 3px 14px;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        
        .method.get { background: #2e7d32; color: #81c784; }
        .method.post { background: #b71c1c; color: #ef9a9a; }
        
        .endpoint-card h3 {
            font-size: 1.3rem;
            margin-bottom: 6px;
        }
        
        .endpoint-card .desc {
            color: #aaa;
            font-size: 0.9rem;
            margin-bottom: 14px;
        }
        
        .endpoint-card .url-display {
            background: rgba(0,0,0,0.3);
            padding: 10px 14px;
            border-radius: 10px;
            font-size: 0.8rem;
            color: #4fc3f7;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            margin-bottom: 12px;
            border: 1px solid rgba(79, 195, 247, 0.1);
        }
        
        .endpoint-card .actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .endpoint-card .actions button {
            padding: 7px 18px;
            border-radius: 30px;
            border: none;
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.3s;
            font-weight: 600;
        }
        
        .btn-copy {
            background: rgba(79, 195, 247, 0.15);
            color: #4fc3f7;
            border: 1px solid rgba(79, 195, 247, 0.3);
        }
        
        .btn-copy:hover {
            background: rgba(79, 195, 247, 0.3);
        }
        
        .btn-open {
            background: rgba(255, 215, 0, 0.15);
            color: #ffd700;
            border: 1px solid rgba(255, 215, 0, 0.3);
        }
        
        .btn-open:hover {
            background: rgba(255, 215, 0, 0.3);
        }
        
        .credit-section {
            text-align: center;
            padding-top: 25px;
            border-top: 1px solid rgba(255,255,255,0.06);
        }
        
        .credit-section .tg-btn {
            display: inline-flex;
            align-items: center;
            gap: 12px;
            background: linear-gradient(135deg, #1da1f2, #0d8bd9);
            color: #fff;
            padding: 14px 35px;
            border-radius: 50px;
            text-decoration: none;
            font-weight: 700;
            font-size: 1.1rem;
            transition: all 0.3s;
            box-shadow: 0 8px 25px rgba(29, 161, 242, 0.3);
        }
        
        .credit-section .tg-btn:hover {
            transform: scale(1.05);
            box-shadow: 0 12px 35px rgba(29, 161, 242, 0.5);
        }
        
        .credit-section .tg-btn i {
            font-size: 1.5rem;
        }
        
        .credit-section .credit-text {
            color: #666;
            font-size: 0.85rem;
            margin-top: 15px;
        }
        
        .credit-section .credit-text strong {
            color: #ffd700;
        }
        
        .toast {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: rgba(0,0,0,0.85);
            backdrop-filter: blur(10px);
            padding: 14px 28px;
            border-radius: 16px;
            border: 1px solid rgba(255,255,255,0.1);
            transform: translateY(100px);
            opacity: 0;
            transition: all 0.5s ease;
            font-size: 0.95rem;
            z-index: 999;
        }
        
        .toast.show {
            transform: translateY(0);
            opacity: 1;
        }
        
        .toast.success { border-color: #4caf50; }
        .toast.error { border-color: #f44336; }
        
        @media (max-width: 600px) {
            .container { padding: 20px 15px; }
            .header h1 { font-size: 2rem; }
            .endpoint-grid { grid-template-columns: 1fr; }
            .base-url-card { flex-direction: column; align-items: stretch; }
        }
    </style>
</head>
<body>

<div class="container">
    
    <div class="header">
        <h1>🔥 FreeFire API</h1>
        <p>Friend Manager — Add / Remove / Player Info</p>
        <span class="badge"><i class="fas fa-code"></i> 3 JWT Methods</span>
    </div>
    
    <div class="base-url-card">
        <div>
            <div class="label"><i class="fas fa-link"></i> Your API Base URL</div>
            <div class="url" id="baseUrl">{base_url}</div>
        </div>
        <button class="copy-btn" onclick="copyBaseUrl()">
            <i class="fas fa-copy"></i> Copy Base URL
        </button>
    </div>
    
    <div class="endpoint-grid">
        
        <!-- ADD FRIEND -->
        <div class="endpoint-card">
            <span class="method get">GET</span>
            <h3><i class="fas fa-user-plus" style="color:#4caf50;"></i> Add Friend</h3>
            <div class="desc">3 Authentication Methods</div>
            <div class="url-display" id="addUrl">{base_url}/add?eat_token=EAT&friend_uid=TARGET</div>
            <div class="url-display" id="addUrl2">{base_url}/add?access_token=TOKEN&friend_uid=TARGET</div>
            <div class="url-display" id="addUrl3">{base_url}/add?uid=UID&password=PASS&friend_uid=TARGET</div>
            <div class="actions">
                <button class="btn-copy" onclick="copyUrl('addUrl')"><i class="fas fa-copy"></i> EAT</button>
                <button class="btn-copy" onclick="copyUrl('addUrl2')"><i class="fas fa-copy"></i> Access</button>
                <button class="btn-copy" onclick="copyUrl('addUrl3')"><i class="fas fa-copy"></i> UID+Pass</button>
            </div>
        </div>
        
        <!-- REMOVE FRIEND -->
        <div class="endpoint-card">
            <span class="method get">GET</span>
            <h3><i class="fas fa-user-minus" style="color:#f44336;"></i> Remove Friend</h3>
            <div class="desc">3 Authentication Methods</div>
            <div class="url-display" id="removeUrl">{base_url}/remove?eat_token=EAT&friend_uid=TARGET</div>
            <div class="url-display" id="removeUrl2">{base_url}/remove?access_token=TOKEN&friend_uid=TARGET</div>
            <div class="url-display" id="removeUrl3">{base_url}/remove?uid=UID&password=PASS&friend_uid=TARGET</div>
            <div class="actions">
                <button class="btn-copy" onclick="copyUrl('removeUrl')"><i class="fas fa-copy"></i> EAT</button>
                <button class="btn-copy" onclick="copyUrl('removeUrl2')"><i class="fas fa-copy"></i> Access</button>
                <button class="btn-copy" onclick="copyUrl('removeUrl3')"><i class="fas fa-copy"></i> UID+Pass</button>
            </div>
        </div>
        
        <!-- PLAYER INFO -->
        <div class="endpoint-card">
            <span class="method get">GET</span>
            <h3><i class="fas fa-id-card" style="color:#4fc3f7;"></i> Player Info</h3>
            <div class="desc">3 Authentication Methods</div>
            <div class="url-display" id="infoUrl">{base_url}/player_info?eat_token=EAT&friend_uid=TARGET</div>
            <div class="url-display" id="infoUrl2">{base_url}/player_info?access_token=TOKEN&friend_uid=TARGET</div>
            <div class="url-display" id="infoUrl3">{base_url}/player_info?uid=UID&password=PASS&friend_uid=TARGET</div>
            <div class="actions">
                <button class="btn-copy" onclick="copyUrl('infoUrl')"><i class="fas fa-copy"></i> EAT</button>
                <button class="btn-copy" onclick="copyUrl('infoUrl2')"><i class="fas fa-copy"></i> Access</button>
                <button class="btn-copy" onclick="copyUrl('infoUrl3')"><i class="fas fa-copy"></i> UID+Pass</button>
            </div>
        </div>
        
        <!-- TOKEN -->
        <div class="endpoint-card">
            <span class="method get">GET</span>
            <h3><i class="fas fa-key" style="color:#ffd700;"></i> Get Token</h3>
            <div class="desc">Generate JWT - 3 Methods</div>
            <div class="url-display" id="tokenUrl">{base_url}/token?eat_token=EAT</div>
            <div class="url-display" id="tokenUrl2">{base_url}/token?access_token=TOKEN</div>
            <div class="url-display" id="tokenUrl3">{base_url}/token?uid=UID&password=PASS</div>
            <div class="actions">
                <button class="btn-copy" onclick="copyUrl('tokenUrl')"><i class="fas fa-copy"></i> EAT</button>
                <button class="btn-copy" onclick="copyUrl('tokenUrl2')"><i class="fas fa-copy"></i> Access</button>
                <button class="btn-copy" onclick="copyUrl('tokenUrl3')"><i class="fas fa-copy"></i> UID+Pass</button>
            </div>
        </div>
        
        <!-- HEALTH -->
        <div class="endpoint-card">
            <span class="method get">GET</span>
            <h3><i class="fas fa-heartbeat" style="color:#4caf50;"></i> Health Check</h3>
            <div class="desc">Check if API is running</div>
            <div class="url-display" id="healthUrl">{base_url}/health</div>
            <div class="actions">
                <button class="btn-copy" onclick="copyUrl('healthUrl')"><i class="fas fa-copy"></i> Copy</button>
                <button class="btn-open" onclick="openUrl('healthUrl')"><i class="fas fa-external-link-alt"></i> Open</button>
            </div>
        </div>
        
    </div>
    
    <div class="credit-section">
        <a href="https://t.me/DRAGON_AARMY_LEGEND_1" target="_blank" class="tg-btn">
            <i class="fab fa-telegram-plane"></i> Join Telegram Channel
        </a>
        <div class="credit-text">
            Made with ❤️ by <strong>@SKY_DROGON</strong> &bull; Channel <strong>@DRAGON_AARMY_LEGEND_1</strong>
        </div>
    </div>
    
</div>

<div class="toast" id="toast"></div>

<script>
    const baseUrl = "{base_url}";
    
    function showToast(msg, type = 'success') {
        const t = document.getElementById('toast');
        t.textContent = msg;
        t.className = 'toast ' + type + ' show';
        clearTimeout(t._timer);
        t._timer = setTimeout(() => t.classList.remove('show'), 2500);
    }
    
    function copyBaseUrl() {
        navigator.clipboard.writeText(baseUrl).then(() => {
            showToast('✅ Base URL copied!', 'success');
        }).catch(() => {
            const el = document.getElementById('baseUrl');
            const range = document.createRange();
            range.selectNode(el);
            window.getSelection().removeAllRanges();
            window.getSelection().addRange(range);
            document.execCommand('copy');
            showToast('✅ Base URL copied!', 'success');
        });
    }
    
    function copyUrl(id) {
        const el = document.getElementById(id);
        const url = el.textContent.trim();
        navigator.clipboard.writeText(url).then(() => {
            showToast('✅ URL copied!', 'success');
        }).catch(() => {
            const range = document.createRange();
            range.selectNode(el);
            window.getSelection().removeAllRanges();
            window.getSelection().addRange(range);
            document.execCommand('copy');
            showToast('✅ URL copied!', 'success');
        });
    }
    
    function openUrl(id) {
        const el = document.getElementById(id);
        const url = el.textContent.trim();
        window.open(url, '_blank');
    }
</script>

</body>
</html>
    '''.replace('{base_url}', host)
    
    return html

@app.route('/add', methods=['GET'])
def adding_friend_custom():
    """URL: 
       /add?eat_token=EAT&friend_uid=TARGET
       /add?access_token=TOKEN&friend_uid=TARGET
       /add?uid=UID&password=PASS&friend_uid=TARGET
    """
    uid = request.args.get('uid')
    password = request.args.get('password')
    access_token = request.args.get('access_token')
    eat_token = request.args.get('eat_token')
    friend_uid = request.args.get('friend_uid')
    server_name = request.args.get('server_name', 'IND')

    if not friend_uid:
        return jsonify({"status": "failed", "message": "Missing friend_uid"}), 400
    
    if not (eat_token or access_token or (uid and password)):
        return jsonify({"status": "failed", "message": "Provide eat_token OR access_token OR (uid+password)"}), 400

    token, error = get_token_common(uid, password, access_token, eat_token)
    if error:
        return jsonify({"status": "failed", "message": error}), 400
    
    author_uid = decode_author_uid(token)
    if not author_uid:
        return jsonify({"status": "failed", "message": "Invalid token"}), 400
        
    result = send_friend_request_with_retry(author_uid, friend_uid, token, server_name)
    return jsonify(result)

@app.route('/remove', methods=['GET'])
def removing_friend_custom():
    """URL: 
       /remove?eat_token=EAT&friend_uid=TARGET
       /remove?access_token=TOKEN&friend_uid=TARGET
       /remove?uid=UID&password=PASS&friend_uid=TARGET
    """
    uid = request.args.get('uid')
    password = request.args.get('password')
    access_token = request.args.get('access_token')
    eat_token = request.args.get('eat_token')
    friend_uid = request.args.get('friend_uid')
    server_name = request.args.get('server_name', 'IND')

    if not friend_uid:
        return jsonify({"status": "failed", "message": "Missing friend_uid"}), 400
    
    if not (eat_token or access_token or (uid and password)):
        return jsonify({"status": "failed", "message": "Provide eat_token OR access_token OR (uid+password)"}), 400

    token, error = get_token_common(uid, password, access_token, eat_token)
    if error:
        return jsonify({"status": "failed", "message": error}), 400
    
    author_uid = decode_author_uid(token)
    if not author_uid:
        return jsonify({"status": "failed", "message": "Invalid token"}), 400
        
    result = remove_friend_with_retry(author_uid, friend_uid, token, server_name)
    return jsonify(result)

@app.route('/player_info', methods=['GET'])
def player_info_custom():
    """URL: 
       /player_info?eat_token=EAT&friend_uid=TARGET
       /player_info?access_token=TOKEN&friend_uid=TARGET
       /player_info?uid=UID&password=PASS&friend_uid=TARGET
    """
    uid = request.args.get('uid')
    password = request.args.get('password')
    access_token = request.args.get('access_token')
    eat_token = request.args.get('eat_token')
    friend_uid = request.args.get('friend_uid')
    server_name = request.args.get('server_name', 'IND')

    if not friend_uid:
        return jsonify({"status": "failed", "message": "Missing friend_uid"}), 400
    
    if not (eat_token or access_token or (uid and password)):
        return jsonify({"status": "failed", "message": "Provide eat_token OR access_token OR (uid+password)"}), 400

    token, error = get_token_common(uid, password, access_token, eat_token)
    if error:
        return jsonify({"status": "failed", "message": error}), 400

    player_info = get_player_info(friend_uid, token, server_name)
    if not player_info:
        return jsonify({"status": "failed", "message": "Info not found"}), 400

    player_data = extract_player_info(player_info)
    player_data.update({"status": "success", "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    return jsonify(player_data)

@app.route('/token', methods=['GET'])
def oauth_guest():
    """Get token using 3 methods:
       /token?eat_token=EAT
       /token?access_token=TOKEN
       /token?uid=UID&password=PASS
    """
    uid = request.args.get('uid')
    password = request.args.get('password')
    access_token = request.args.get('access_token')
    eat_token = request.args.get('eat_token')
    
    if eat_token:
        token, error = get_jwt_from_eat_token(eat_token)
        if error:
            return jsonify({"status": "failed", "message": error}), 400
        
        author_uid = decode_author_uid(token)
        return jsonify({
            "status": "success",
            "token": token,
            "author_uid": author_uid,
            "method": "eat_token"
        })
    
    elif access_token:
        token, error = get_jwt_from_access_token(access_token)
        if error:
            return jsonify({"status": "failed", "message": error}), 400
        
        author_uid = decode_author_uid(token)
        return jsonify({
            "status": "success",
            "token": token,
            "author_uid": author_uid,
            "method": "access_token"
        })
    
    elif uid and password:
        token, error = get_jwt_from_uid_password(uid, password)
        if error:
            return jsonify({"status": "failed", "message": error}), 400
            
        author_uid = decode_author_uid(token)
        if not author_uid:
            return jsonify({"status": "failed", "message": "Generated token is invalid"}), 400
            
        return jsonify({
            "status": "success",
            "token": token,
            "uid": uid,
            "author_uid": author_uid,
            "method": "uid_password"
        })
    
    else:
        return jsonify({"status": "failed", "message": "Provide eat_token OR access_token OR (uid+password)"}), 400

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "FreeFire-API"}), 200

# -----------------------------
# Run Server
# -----------------------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)