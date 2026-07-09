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
import my_pb2
import output_pb2
from datetime import datetime
import json
import time
import urllib3
import warnings
import base64

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
# ACCESS TOKEN -> JWT (Major Login)
# -----------------------------

# Protobuf definitions for Major Login
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

_sym_db = _symbol_database.Default()

# MajorLoginReq protobuf
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13MajorLoginReq.proto\"\xfa\n\n\nMajorLogin\x12\x12\n\nevent_time\x18\x03 \x01(\t\x12\x11\n\tgame_name\x18\x04 \x01(\t\x12\x13\n\x0bplatform_id\x18\x05 \x01(\x05\x12\x16\n\x0e\x63lient_version\x18\x07 \x01(\t\x12\x17\n\x0fsystem_software\x18\x08 \x01(\t\x12\x17\n\x0fsystem_hardware\x18\t \x01(\t\x12\x18\n\x10telecom_operator\x18\n \x01(\t\x12\x14\n\x0cnetwork_type\x18\x0b \x01(\t\x12\x14\n\x0cscreen_width\x18\x0c \x01(\r\x12\x15\n\rscreen_height\x18\r \x01(\r\x12\x12\n\nscreen_dpi\x18\x0e \x01(\t\x12\x19\n\x11processor_details\x18\x0f \x01(\t\x12\x0e\n\x06memory\x18\x10 \x01(\r\x12\x14\n\x0cgpu_renderer\x18\x11 \x01(\t\x12\x13\n\x0bgpu_version\x18\x12 \x01(\t\x12\x18\n\x10unique_device_id\x18\x13 \x01(\t\x12\x11\n\tclient_ip\x18\x14 \x01(\t\x12\x10\n\x08language\x18\x15 \x01(\t\x12\x0f\n\x07open_id\x18\x16 \x01(\t\x12\x14\n\x0copen_id_type\x18\x17 \x01(\t\x12\x13\n\x0b\x64\x65vice_type\x18\x18 \x01(\t\x12\'\n\x10memory_available\x18\x19 \x01(\x0b\x32\r.GameSecurity\x12\x14\n\x0c\x61\x63\x63\x65ss_token\x18\x1d \x01(\t\x12\x17\n\x0fplatform_sdk_id\x18\x1e \x01(\x05\x12\x1a\n\x12network_operator_a\x18) \x01(\t\x12\x16\n\x0enetwork_type_a\x18* \x01(\t\x12\x1c\n\x14\x63lient_using_version\x18\x39 \x01(\t\x12\x1e\n\x16\x65xternal_storage_total\x18< \x01(\x05\x12\"\n\x1a\x65xternal_storage_available\x18= \x01(\x05\x12\x1e\n\x16internal_storage_total\x18> \x01(\x05\x12\"\n\x1ainternal_storage_available\x18? \x01(\x05\x12#\n\x1bgame_disk_storage_available\x18@ \x01(\x05\x12\x1f\n\x17game_disk_storage_total\x18\x41 \x01(\x05\x12%\n\x1d\x65xternal_sdcard_avail_storage\x18\x42 \x01(\x05\x12%\n\x1d\x65xternal_sdcard_total_storage\x18\x43 \x01(\x05\x12\x10\n\x08login_by\x18I \x01(\x05\x12\x14\n\x0clibrary_path\x18J \x01(\t\x12\x12\n\nreg_avatar\x18L \x01(\x05\x12\x15\n\rlibrary_token\x18M \x01(\t\x12\x14\n\x0c\x63hannel_type\x18N \x01(\x05\x12\x10\n\x08\x63pu_type\x18O \x01(\x05\x12\x18\n\x10\x63pu_architecture\x18Q \x01(\t\x12\x1b\n\x13\x63lient_version_code\x18S \x01(\t\x12\x14\n\x0cgraphics_api\x18V \x01(\t\x12\x1d\n\x15supported_astc_bitset\x18W \x01(\r\x12\x1a\n\x12login_open_id_type\x18X \x01(\x05\x12\x18\n\x10\x61nalytics_detail\x18Y \x01(\x0c\x12\x14\n\x0cloading_time\x18\\ \x01(\r\x12\x17\n\x0frelease_channel\x18] \x01(\t\x12\x12\n\nextra_info\x18^ \x01(\t\x12 \n\x18\x61ndroid_engine_init_flag\x18_ \x01(\r\x12\x0f\n\x07if_push\x18\x61 \x01(\x05\x12\x0e\n\x06is_vpn\x18\x62 \x01(\x05\x12\x1c\n\x14origin_platform_type\x18\x63 \x01(\t\x12\x1d\n\x15primary_platform_type\x18\x64 \x01(\t\"5\n\x0cGameSecurity\x12\x0f\n\x07version\x18\x06 \x01(\x05\x12\x14\n\x0chidden_value\x18\x08 \x01(\x04\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'MajorLoginReq_pb2', _globals)
MajorLogin = _globals['MajorLogin']
GameSecurity = _globals['GameSecurity']

# MajorLoginRes protobuf
DESCRIPTOR2 = _descriptor_pool.Default().AddSerializedFile(b'\n\x13MajorLoginRes.proto\"|\n\rMajorLoginRes\x12\x13\n\x0b\x61\x63\x63ount_uid\x18\x01 \x01(\x04\x12\x0e\n\x06region\x18\x02 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\x0b\n\x03url\x18\n \x01(\t\x12\x11\n\ttimestamp\x18\x15 \x01(\x03\x12\x0b\n\x03key\x18\x16 \x01(\x0c\x12\n\n\x02iv\x18\x17 \x01(\x0c\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR2, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR2, 'MajorLoginRes_pb2', _globals)
MajorLoginRes = _globals['MajorLoginRes']

def get_jwt_from_access_token(access_token):
    """Convert access token to JWT using Major Login"""
    try:
        # Step 1: Get open_id from token inspect endpoint
        inspect_url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
        insp_resp = requests.get(inspect_url, timeout=10)
        
        if insp_resp.status_code != 200:
            return None, "Failed to inspect token"
        
        insp_data = insp_resp.json()
        open_id = insp_data.get('open_id')
        
        if not open_id:
            return None, "open_id not found in token"
        
        # Step 2: Try different platform types
        platform_types = [2, 3, 4, 6, 8]
        
        for pt in platform_types:
            try:
                major = MajorLogin()
                major.event_time = "2025-03-23 12:00:00"
                major.game_name = "free fire"
                major.platform_id = 1
                major.client_version = "1.126.2"
                major.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
                major.system_hardware = "Handheld"
                major.telecom_operator = "Verizon"
                major.network_type = "WIFI"
                major.screen_width = 1920
                major.screen_height = 1080
                major.screen_dpi = "280"
                major.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
                major.memory = 3003
                major.gpu_renderer = "Adreno (TM) 640"
                major.gpu_version = "OpenGL ES 3.1 v1.46"
                major.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
                major.client_ip = "223.191.51.89"
                major.language = "en"
                major.open_id = open_id
                major.open_id_type = "4"
                major.device_type = "Handheld"
                major.memory_available.version = 55
                major.memory_available.hidden_value = 81
                major.access_token = access_token
                major.platform_sdk_id = 1
                major.network_operator_a = "Verizon"
                major.network_type_a = "WIFI"
                major.client_using_version = "7428b253defc164018c604a1ebbfebdf"
                major.external_storage_total = 36235
                major.external_storage_available = 31335
                major.internal_storage_total = 2519
                major.internal_storage_available = 703
                major.game_disk_storage_available = 25010
                major.game_disk_storage_total = 26628
                major.external_sdcard_avail_storage = 32992
                major.external_sdcard_total_storage = 36235
                major.login_by = 3
                major.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
                major.reg_avatar = 1
                major.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
                major.channel_type = 3
                major.cpu_type = 2
                major.cpu_architecture = "64"
                major.client_version_code = "2019118695"
                major.graphics_api = "OpenGLES2"
                major.supported_astc_bitset = 16383
                major.login_open_id_type = 4
                major.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWA0FUgsvA1snWlBaO1kFYg=="
                major.loading_time = 13564
                major.release_channel = "android"
                major.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
                major.android_engine_init_flag = 110009
                major.if_push = 1
                major.is_vpn = 1
                major.origin_platform_type = str(pt)
                major.primary_platform_type = str(pt)
                
                payload = major.SerializeToString()
                encrypted_payload = encrypt_message(payload)
                
                url = "https://loginbp.ggblueshark.com/MajorLogin"
                headers = {
                    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
                    "Connection": "Keep-Alive",
                    "Accept-Encoding": "gzip",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Unity-Version": "2018.4.11f1",
                    "X-GA": "v1 1",
                    "ReleaseVersion": "OB54"
                }
                
                resp = requests.post(url, data=encrypted_payload, headers=headers, verify=False, timeout=10)
                
                if resp.status_code == 200:
                    major_res = MajorLoginRes()
                    major_res.ParseFromString(resp.content)
                    if major_res.token:
                        return major_res.token, None
            except Exception as e:
                continue
        
        return None, "MajorLogin failed on all platforms"
        
    except Exception as e:
        return None, str(e)

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
# JWT Token Generation Functions
# -----------------------------
def get_token_from_uid_password(uid, password):
    """Get JWT token using UID and password"""
    try:
        oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        payload = {
            'uid': uid,
            'password': password,
            'response_type': "token",
            'client_type': "2",
            'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            'client_id': "100067"
        }
        
        headers = {
            'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip"
        }

        oauth_response = requests.post(oauth_url, data=payload, headers=headers, timeout=10, verify=False)
        oauth_response.raise_for_status()
        
        oauth_data = oauth_response.json()
        
        if 'access_token' not in oauth_data:
            return None, "OAuth response missing access_token"

        access_token = oauth_data['access_token']
        open_id = oauth_data.get('open_id', '')
        
        platforms = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        
        for platform_type in platforms:
            result = try_platform_login(open_id, access_token, platform_type)
            if result and 'token' in result:
                return result['token'], None
        
        return None, "Login successful but JWT generation failed on all platforms"

    except requests.RequestException as e:
        return None, f"OAuth request failed: {str(e)}"
    except ValueError:
        return None, "Invalid JSON response from OAuth service"
    except Exception as e:
        return None, f"Unexpected error: {str(e)}"

def try_platform_login(open_id, access_token, platform_type):
    """Try login for a specific platform"""
    try:
        game_data = my_pb2.GameData()
        game_data.timestamp = "2024-12-05 18:15:32"
        game_data.game_name = "free fire"
        game_data.game_version = 1
        game_data.version_code = "1.108.3"
        game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
        game_data.device_type = "Handheld"
        game_data.network_provider = "Verizon Wireless"
        game_data.connection_type = "WIFI"
        game_data.screen_width = 1280
        game_data.screen_height = 960
        game_data.dpi = "240"
        game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
        game_data.total_ram = 5951
        game_data.gpu_name = "Adreno (TM) 640"
        game_data.gpu_version = "OpenGL ES 3.0"
        game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
        game_data.ip_address = "172.190.111.97"
        game_data.language = "en"
        game_data.open_id = open_id
        game_data.access_token = access_token
        game_data.platform_type = platform_type
        game_data.field_99 = str(platform_type)
        game_data.field_100 = str(platform_type)

        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(serialized_data)
        hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB54"
        }
        
        edata = bytes.fromhex(hex_encrypted_data)

        response = requests.post(url, data=edata, headers=headers, timeout=10, verify=False)
        response.raise_for_status()

        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            example_msg.ParseFromString(response.content)
            data_dict = {field.name: getattr(example_msg, field.name)
                         for field in example_msg.DESCRIPTOR.fields
                         if field.name not in ["binary", "binary_data", "Garena420"]}

            if data_dict and "token" in data_dict:
                token_value = data_dict["token"]
                try:
                    decoded_token = jwt.decode(token_value, options={"verify_signature": False})
                except Exception:
                    decoded_token = {}

                return {
                    "account_id": decoded_token.get("account_id"),
                    "account_name": decoded_token.get("nickname"),
                    "open_id": open_id,
                    "access_token": access_token,
                    "platform": decoded_token.get("external_type"),
                    "region": decoded_token.get("lock_region"),
                    "status": "success",
                    "token": token_value
                }
        
        return None

    except Exception:
        return None

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

def get_token_common(uid=None, password=None, access_token=None):
    """Common function to get token from either uid/password or access_token"""
    token = None
    error = None
    
    if access_token:
        # Direct access token to JWT
        token, error = get_jwt_from_access_token(access_token)
        if error:
            return None, error
    elif uid and password:
        # UID/Password to JWT
        token, error = get_token_from_uid_password(uid, password)
        if error:
            return None, error
    else:
        return None, "Missing authentication (uid/password or access_token)"
    
    return token, None

# -----------------------------
# Routes - WITH ACCESS TOKEN SUPPORT
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
        
        /* ===== BASE URL CARD ===== */
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
        
        /* ===== ENDPOINT GRID ===== */
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
        
        /* ===== CREDIT SECTION ===== */
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
        
        /* ===== TOAST ===== */
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
        
        /* ===== RESPONSIVE ===== */
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
    
    <!-- HEADER -->
    <div class="header">
        <h1>🔥 FreeFire API</h1>
        <p>Friend Manager — Add / Remove / Player Info</p>
        <span class="badge"><i class="fas fa-code"></i> Endpoints</span>
    </div>
    
    <!-- BASE URL -->
    <div class="base-url-card">
        <div>
            <div class="label"><i class="fas fa-link"></i> Your API Base URL</div>
            <div class="url" id="baseUrl">{base_url}</div>
        </div>
        <button class="copy-btn" onclick="copyBaseUrl()">
            <i class="fas fa-copy"></i> Copy Base URL
        </button>
    </div>
    
    <!-- ENDPOINTS -->
    <div class="endpoint-grid">
        
        <!-- ADD FRIEND -->
        <div class="endpoint-card">
            <span class="method get">GET</span>
            <h3><i class="fas fa-user-plus" style="color:#4caf50;"></i> Add Friend</h3>
            <div class="desc">Send friend request to target UID</div>
            <div class="url-display" id="addUrl">{base_url}/add?uid=UID&password=PASS&friend_uid=TARGET</div>
            <div class="actions">
                <button class="btn-copy" onclick="copyUrl('addUrl')"><i class="fas fa-copy"></i> Copy</button>
                <button class="btn-open" onclick="openUrl('addUrl')"><i class="fas fa-external-link-alt"></i> Open</button>
            </div>
        </div>
        
        <!-- REMOVE FRIEND -->
        <div class="endpoint-card">
            <span class="method get">GET</span>
            <h3><i class="fas fa-user-minus" style="color:#f44336;"></i> Remove Friend</h3>
            <div class="desc">Remove friend by target UID</div>
            <div class="url-display" id="removeUrl">{base_url}/remove?uid=UID&password=PASS&friend_uid=TARGET</div>
            <div class="actions">
                <button class="btn-copy" onclick="copyUrl('removeUrl')"><i class="fas fa-copy"></i> Copy</button>
                <button class="btn-open" onclick="openUrl('removeUrl')"><i class="fas fa-external-link-alt"></i> Open</button>
            </div>
        </div>
        
        <!-- PLAYER INFO -->
        <div class="endpoint-card">
            <span class="method get">GET</span>
            <h3><i class="fas fa-id-card" style="color:#4fc3f7;"></i> Player Info</h3>
            <div class="desc">Get detailed player information</div>
            <div class="url-display" id="infoUrl">{base_url}/player_info?uid=UID&password=PASS&friend_uid=TARGET</div>
            <div class="actions">
                <button class="btn-copy" onclick="copyUrl('infoUrl')"><i class="fas fa-copy"></i> Copy</button>
                <button class="btn-open" onclick="openUrl('infoUrl')"><i class="fas fa-external-link-alt"></i> Open</button>
            </div>
        </div>
        
        <!-- TOKEN -->
        <div class="endpoint-card">
            <span class="method get">GET</span>
            <h3><i class="fas fa-key" style="color:#ffd700;"></i> Get Token</h3>
            <div class="desc">Generate JWT from UID+Password or Access Token</div>
            <div class="url-display" id="tokenUrl">{base_url}/token?uid=UID&password=PASS</div>
            <div class="actions">
                <button class="btn-copy" onclick="copyUrl('tokenUrl')"><i class="fas fa-copy"></i> Copy</button>
                <button class="btn-open" onclick="openUrl('tokenUrl')"><i class="fas fa-external-link-alt"></i> Open</button>
            </div>
        </div>
        
        <!-- HEALTH (Extra) -->
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
        
        <!-- ACCESS TOKEN VERSION (Extra) -->
        <div class="endpoint-card">
            <span class="method get">GET</span>
            <h3><i class="fas fa-shield-alt" style="color:#ab47bc;"></i> With Access Token</h3>
            <div class="desc">Use access_token instead of uid+pass</div>
            <div class="url-display" id="accessUrl">{base_url}/add?access_token=TOKEN&friend_uid=TARGET</div>
            <div class="actions">
                <button class="btn-copy" onclick="copyUrl('accessUrl')"><i class="fas fa-copy"></i> Copy</button>
                <button class="btn-open" onclick="openUrl('accessUrl')"><i class="fas fa-external-link-alt"></i> Open</button>
            </div>
        </div>
        
    </div>
    
    <!-- CREDIT + TELEGRAM -->
    <div class="credit-section">
        <a href="https://t.me/DRAGON_AARMY_LEGEND_1" target="_blank" class="tg-btn">
            <i class="fab fa-telegram-plane"></i> Join Telegram Channel
        </a>
        <div class="credit-text">
            Made with ❤️ by <strong>@SKY_DROGON</strong> &bull; Channel <strong>@DRAGON_AARMY_LEGEND_1</strong>
        </div>
    </div>
    
</div>

<!-- TOAST -->
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
            // Fallback
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
       /add?uid=UID&password=PASS&friend_uid=TARGET
       OR
       /add?access_token=TOKEN&friend_uid=TARGET
    """
    uid = request.args.get('uid')
    password = request.args.get('password')
    access_token = request.args.get('access_token')
    friend_uid = request.args.get('friend_uid')
    server_name = request.args.get('server_name', 'IND')

    if not friend_uid:
        return jsonify({"status": "failed", "message": "Missing friend_uid"}), 400
    
    if not access_token and (not uid or not password):
        return jsonify({"status": "failed", "message": "Provide either (uid+password) or access_token"}), 400

    token, error = get_token_common(uid, password, access_token)
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
       /remove?uid=UID&password=PASS&friend_uid=TARGET
       OR
       /remove?access_token=TOKEN&friend_uid=TARGET
    """
    uid = request.args.get('uid')
    password = request.args.get('password')
    access_token = request.args.get('access_token')
    friend_uid = request.args.get('friend_uid')
    server_name = request.args.get('server_name', 'IND')

    if not friend_uid:
        return jsonify({"status": "failed", "message": "Missing friend_uid"}), 400
    
    if not access_token and (not uid or not password):
        return jsonify({"status": "failed", "message": "Provide either (uid+password) or access_token"}), 400

    token, error = get_token_common(uid, password, access_token)
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
       /player_info?uid=UID&password=PASS&friend_uid=TARGET
       OR
       /player_info?access_token=TOKEN&friend_uid=TARGET
    """
    uid = request.args.get('uid')
    password = request.args.get('password')
    access_token = request.args.get('access_token')
    friend_uid = request.args.get('friend_uid')
    server_name = request.args.get('server_name', 'IND')

    if not friend_uid:
        return jsonify({"status": "failed", "message": "Missing friend_uid"}), 400
    
    if not access_token and (not uid or not password):
        return jsonify({"status": "failed", "message": "Provide either (uid+password) or access_token"}), 400

    token, error = get_token_common(uid, password, access_token)
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
    """Get token using UID and password OR access_token"""
    uid = request.args.get('uid')
    password = request.args.get('password')
    access_token = request.args.get('access_token')
    
    if access_token:
        token, error = get_jwt_from_access_token(access_token)
        if error:
            return jsonify({"message": error}), 400
        
        author_uid = decode_author_uid(token)
        return jsonify({
            "status": "success",
            "token": token,
            "author_uid": author_uid,
            "method": "access_token"
        })
    
    elif uid and password:
        token, error = get_token_from_uid_password(uid, password)
        if error:
            return jsonify({"message": error}), 400
            
        author_uid = decode_author_uid(token)
        if not author_uid:
            return jsonify({"message": "Generated token is invalid"}), 400
            
        return jsonify({
            "status": "success",
            "token": token,
            "uid": uid,
            "author_uid": author_uid,
            "method": "uid_password"
        })
    
    else:
        return jsonify({"message": "Provide either (uid+password) or access_token"}), 400

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "FreeFire-API"}), 200

# -----------------------------
# Run Server
# -----------------------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050)