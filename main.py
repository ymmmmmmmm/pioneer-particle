import hashlib
import json
import random
import re
import time
import uuid
from base64 import b64encode

import requests
import tls_client
from eth_abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from faker import Faker
from loguru import logger
from web3 import Web3
from config import project_uuid, project_client_key, project_app_uuid, yescaptcha_client_key

fake = Faker(locale='en-US')

op_w3 = Web3(Web3.HTTPProvider('https://optimism-sepolia.blockpi.network/v1/rpc/public'))
base_w3 = Web3(Web3.HTTPProvider('https://base-sepolia.blockpi.network/v1/rpc/public'))


def get_turnstile_token():
    while True:
        json_data = {
            "clientKey": yescaptcha_client_key,
            "task":
                {
                    "type": "TurnstileTaskProxylessM1",
                    "websiteURL": "https://launchpad.ally.build/zh-CN/signup",
                    "websiteKey": "0x4AAAAAAAPesjutGoykVbu0"
                }, "softID": 109
        }
        response = requests.post(url='https://api.yescaptcha.com/createTask', json=json_data).json()
        if response['errorId'] != 0:
            raise ValueError(response)
        task_id = response['taskId']
        time.sleep(5)
        for _ in range(30):
            data = {"clientKey": yescaptcha_client_key, "taskId": task_id}
            response = requests.post(url='https://api.yescaptcha.com/getTaskResult', json=data).json()
            if response['status'] == 'ready':
                return response['solution']['token']
            else:
                time.sleep(2)


def build_trackers(user_agent) -> str:
    return b64encode(json.dumps({"os": "Mac OS X", "browser": "Safari", "device": "", "system_locale": "zh-CN",
                                 "browser_user_agent": user_agent,
                                 "browser_version": "13.1.twitter_account", "os_version": "10.13.6", "referrer": "",
                                 "referring_domain": "", "referrer_current": "", "referring_domain_current": "",
                                 "release_channel": "stable", "client_build_number": 177662,
                                 "client_event_source": None}, separators=(',', ':')).encode()).decode()


def authorize_discord(discord_token, proxies=None):
    try:
        session = tls_client.Session(random_tls_extension_order=True)
        user_agent = fake.safari()
        headers = {
            'Host': 'discord.com',
            'Connection': 'keep-alive',
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        }
        _uuid = uuid.uuid4()
        response = session.get(
            url=f'https://discord.com/api/oauth2/authorize?client_id=1229361725870964818&redirect_uri=https://pioneer.particle.network/signup&response_type=code&scope=identify%20email&state=discord-{_uuid}',
            headers=headers, allow_redirects=False, proxy=proxies)
        logger.debug(response)
        x_super_properties = build_trackers(user_agent)
        headers.update({"Authorization": discord_token})
        headers.update({"X-Super-Properties": x_super_properties})
        headers.update({"X-Debug-Options": 'bugReporterEnabled'})
        response = session.get(
            url=f'https://discord.com/oauth2/authorize?client_id=1229361725870964818&redirect_uri=https://pioneer.particle.network/signup&response_type=code&scope=identify%20email&state=discord-{_uuid}',
            headers=headers, allow_redirects=False, proxy=proxies)
        logger.debug(response.status_code)
        data = {"permissions": "0", "authorize": True, "integration_type": 0}
        response = session.post(
            url=f'https://discord.com/api/v9/oauth2/authorize?client_id=1229361725870964818&response_type=code&redirect_uri=https://pioneer.particle.network/signup&scope=identify%20email&state=discord-{_uuid}',
            headers=headers, allow_redirects=False, json=data, proxy=proxies).json()
        logger.debug(response)
        location = response['location']
        code = re.findall('code=(.*?)&state=', location)[0]
        return code
    except Exception as e:
        logger.error(e)


def authorize_twitter(twitter_token, proxies=None):
    try:
        session = requests.session()
        session.proxies = proxies
        response = session.get(url='https://twitter.com/home', cookies={
            'auth_token': twitter_token,
            'ct0': '960eb16898ea5b715b54e54a8f58c172'
        })
        ct0 = re.findall('ct0=(.*?);', dict(response.headers)['set-cookie'])[0]
        cookies = {'ct0': ct0, 'auth_token': twitter_token}
        params = {
            'response_type': 'code',
            'client_id': 'c1h0S1pfb010TEVBUnh2N3U3MU86MTpjaQ',
            'redirect_uri': 'https://pioneer.particle.network/signup',
            'scope': 'tweet.read users.read',
            'state': f'twitter-{uuid.uuid4()}',
            'code_challenge': 'challenge',
            'code_challenge_method': 'plain',
        }

        headers = {'authority': 'twitter.com', 'accept': '*/*', 'accept-language': 'zh-CN,zh;q=0.9',
                   'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
                   'cache-control': 'no-cache', 'content-type': 'application/json', 'origin': 'https://twitter.com',
                   'pragma': 'no-cache', 'referer': 'https://twitter.com/puffer_finance/status/1751954283052810298',
                   'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
                   'x-csrf-token': ct0}

        response = session.get('https://twitter.com/i/api/2/oauth2/authorize', params=params, cookies=cookies,
                               headers=headers).json()
        auth_code = response['auth_code']
        data = {'approval': True, 'code': auth_code}
        response = session.post('https://twitter.com/i/api/2/oauth2/authorize', json=data, cookies=cookies,
                                headers=headers).json()
        redirect_uri = response['redirect_uri']
        return redirect_uri
    except Exception as e:
        logger.error(e)


def sha256(data):
    hash_object = hashlib.sha256()
    hash_object.update(json.dumps(data).replace(' ', '').encode())
    hex_dig = hash_object.hexdigest()
    return hex_dig


def register(twitter_token, discord_token):
    try:
        proxies = None
        session = requests.session()
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Auth-Type': 'Basic',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Origin': 'https://pioneer.particle.network',
            'Referer': 'https://pioneer.particle.network/',
            'authorization': 'Basic OUMzUnRxQmNCcUJuQk5vYjo3RGJubng3QlBxOENBOFBI',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        }
        random_str, timestamp, device_id = str(uuid.uuid4()), int(time.time()), str(uuid.uuid4())
        account = Account.create()
        logger.debug(account.address)
        logger.debug(account.key.hex())
        params = {'timestamp': timestamp, 'random_str': random_str, 'device_id': device_id, 'sdk_version': 'web_1.0.0',
                  'project_uuid': project_uuid, 'project_client_key': project_client_key,
                  'project_app_uuid': project_app_uuid}
        sign_str = f"""Welcome to Particle Pioneer!\n\nWallet address:\n{account.address}\n\nNonce:\n{device_id}"""
        signature = account.sign_message(encode_defunct(text=sign_str)).signature.hex()
        mac_info = {"timestamp": timestamp, "random_str": random_str, "device_id": device_id,
                    "sdk_version": "web_1.0.0",
                    "project_uuid": project_uuid, "project_client_key": project_client_key,
                    "mac_key": "5706dd1db5aabc45c649ecc01fdac97100de8e8655715d810d0fb2080e6cea24",
                    "project_app_uuid": project_app_uuid, "loginMethod": "evm_wallet", "loginSource": "metamask",
                    "loginInfo": {"address": account.address.lower(), "signature": signature}}

        mac = sha256(dict(sorted(mac_info.items())))
        params.update({'mac': mac})
        json_data = {'loginMethod': 'evm_wallet', 'loginSource': 'metamask',
                     'loginInfo': {'address': account.address.lower(), 'signature': signature}}
        response = session.post('https://pioneer-api.particle.network/users', params=params, headers=headers,
                                json=json_data).json()
        logger.debug(response)
        mac_key, token = response['macKey'], response['token']
        headers.update({'authorization': f'Basic {token}'})
        random_str, timestamp = str(uuid.uuid4()), int(time.time())
        mac_info = {"timestamp": timestamp, "random_str": random_str, "device_id": device_id,
                    "sdk_version": "web_1.0.0",
                    "project_uuid": project_uuid, "project_client_key": project_client_key,
                    "project_app_uuid": project_app_uuid, "code": "UMK2ER", "mac_key": mac_key}

        params = {'timestamp': timestamp, 'random_str': random_str, 'device_id': device_id, 'sdk_version': 'web_1.0.0',
                  'project_uuid': project_uuid, 'project_client_key': project_client_key,
                  'project_app_uuid': project_app_uuid, 'mac': sha256(dict(sorted(mac_info.items())))}
        json_data = {'code': 'UMK2ER'}

        response = session.post('https://pioneer-api.particle.network/users/invitation_code', params=params,
                                headers=headers, json=json_data).json()
        logger.debug(response)
        redirect_uri = authorize_twitter(twitter_token, proxies)
        twitter_code = redirect_uri.split('=')[2]
        response = session.get(redirect_uri, headers=headers)
        logger.debug(response.status_code)
        turnstile_token = get_turnstile_token()
        random_str, timestamp = str(uuid.uuid4()), int(time.time())
        mac_info = {"timestamp": timestamp, "random_str": random_str, "device_id": device_id,
                    "sdk_version": "web_1.0.0",
                    "project_uuid": project_uuid, "project_client_key": project_client_key,
                    "project_app_uuid": project_app_uuid, "code": twitter_code, "provider": "twitter",
                    "cfTurnstileResponse": turnstile_token, "mac_key": mac_key}

        params = {'timestamp': timestamp, 'random_str': random_str, 'device_id': device_id, 'sdk_version': 'web_1.0.0',
                  'project_uuid': project_uuid, 'project_client_key': project_client_key,
                  'project_app_uuid': project_app_uuid, 'mac': sha256(dict(sorted(mac_info.items())))}
        json_data = {'code': twitter_code, 'provider': 'twitter', 'cfTurnstileResponse': turnstile_token}

        response = session.post('https://pioneer-api.particle.network/users/bind', params=params, headers=headers,
                                json=json_data).json()
        logger.debug(response)
        if not response.get('twitterId', None):
            logger.warning(f'绑定推特失败')
            with open('twitter_fail.txt', 'a+') as f:
                f.writelines(f'{twitter_token}----{discord_token}\n')
            return
        discord_code = authorize_discord(discord_token, proxies)
        turnstile_token = get_turnstile_token()

        random_str, timestamp = str(uuid.uuid4()), int(time.time())
        mac_info = {"timestamp": timestamp, "random_str": random_str, "device_id": device_id,
                    "sdk_version": "web_1.0.0",
                    "project_uuid": project_uuid, "project_client_key": project_client_key,
                    "project_app_uuid": project_app_uuid, "code": discord_code, "provider": "discord",
                    "cfTurnstileResponse": turnstile_token, "mac_key": mac_key}

        params = {'timestamp': timestamp, 'random_str': random_str, 'device_id': device_id, 'sdk_version': 'web_1.0.0',
                  'project_uuid': project_uuid, 'project_client_key': project_client_key,
                  'project_app_uuid': project_app_uuid, 'mac': sha256(dict(sorted(mac_info.items())))}

        json_data = {'code': discord_code, 'provider': 'discord', 'cfTurnstileResponse': turnstile_token}

        response = session.post('https://pioneer-api.particle.network/users/bind', params=params, headers=headers,
                                json=json_data).json()
        logger.debug(response)
        if not response.get('discordId', None):
            logger.warning(f'绑定discord失败')
            with open('discord_fail.txt', 'a+') as f:
                f.writelines(
                    f'{twitter_token}----{discord_token}----{account.address}----{account.key.hex()}\n')
            return
        aa_address = response['aaAddress']
        with open('success.txt', 'a+') as f:
            f.writelines(
                f'{account.address}----{account.key.hex()}----{aa_address}----{mac_key}----{device_id}----{token}----{twitter_token}----{discord_token}\n')
    except Exception as e:
        logger.error(e)
        logger.exception()


def deposit_eth(address, key, mac_key, device_id, token):
    session = requests.session()
    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'zh-CN,zh;q=0.9',
        'authorization': f'Bearer {token}',
        'cache-control': 'no-cache',
        'content-type': 'application/json',
        'origin': 'https://pioneer.particle.network',
        'referer': 'https://pioneer.particle.network/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    }
    amount = int(0.1 * 1e18)
    # 11155420 op
    chain_id = 11155420
    random_str, timestamp = str(uuid.uuid4()), int(time.time())
    mac_info = {"timestamp": timestamp, "random_str": random_str,
                "device_id": device_id, "sdk_version": "web_1.0.0",
                "project_uuid": project_uuid,
                "project_client_key": project_client_key,
                "project_app_uuid": project_app_uuid, "chainId": chain_id,
                "tokenAddress": "0x0000000000000000000000000000000000000000", "amount": str(amount),
                "mac_key": mac_key}
    params = {'timestamp': timestamp, 'random_str': random_str, 'device_id': device_id, 'sdk_version': 'web_1.0.0',
              'project_uuid': project_uuid, 'project_client_key': project_client_key,
              'project_app_uuid': project_app_uuid, 'mac': sha256(dict(sorted(mac_info.items())))}
    json_data = {'chainId': chain_id, 'tokenAddress': '0x0000000000000000000000000000000000000000',
                 'amount': str(amount)}

    response = session.post('https://pioneer-api.particle.network/deposits/deposit_tx', params=params, headers=headers,
                            json=json_data).json()
    logger.debug(response)
    nonce = op_w3.eth.get_transaction_count(address)
    signed_txn = op_w3.eth.account.sign_transaction(
        dict(chainId=chain_id, nonce=nonce, gasPrice=int(op_w3.eth.gas_price * 1.05),
             gas=80000 + random.randint(1, 10000),
             to=op_w3.to_checksum_address(response['tx']['to']), data=response['tx']['data'],
             value=int(response['tx']['value'], 16)), key)
    order_hash = op_w3.eth.send_raw_transaction(signed_txn.rawTransaction).hex()
    logger.debug(order_hash)
    random_str, timestamp = str(uuid.uuid4()), int(time.time())

    mac_info = {"timestamp": timestamp, "random_str": random_str,
                "device_id": device_id, "sdk_version": "web_1.0.0",
                "project_uuid": project_uuid,
                "project_client_key": project_client_key,
                "project_app_uuid": project_app_uuid, "chainId": chain_id,
                "txn": order_hash,
                "mac_key": mac_key}

    params = {
        'timestamp': timestamp,
        'random_str': random_str,
        'device_id': device_id,
        'sdk_version': 'web_1.0.0',
        'project_uuid': project_uuid,
        'project_client_key': project_client_key,
        'project_app_uuid': project_app_uuid,
        'mac': sha256(dict(sorted(mac_info.items())))
    }

    json_data = {
        'chainId': chain_id,
        'txn': order_hash,
    }

    response = session.post('https://pioneer-api.particle.network/deposits', params=params, headers=headers,
                            json=json_data).json()
    logger.debug(response)


def get_signature(merkle_root_result, signature, evm_signature):
    encode_data = ''
    valid_until = merkle_root_result['data'][0]['validUntil']
    valid_after = merkle_root_result['data'][0]['validAfter']
    encode_data += signature[0:130]
    encode_data += '0000000000000000000000000000000000000000000000000000000000000160'
    encode_data += encode(('uint256',), (valid_until,)).hex()
    encode_data += encode(('uint256',), (valid_after,)).hex()
    encode_data += merkle_root_result['merkleRoot'][2:]
    encode_data += '00000000000000000000000000000000000000000000000000000000000000a0'
    encode_data += '00000000000000000000000000000000000000000000000000000000000000e0'
    encode_data += '0000000000000000000000000000000000000000000000000000000000000001'
    result_signature1 = encode_data + merkle_root_result['data'][0]['merkleProof'][0][2:]
    result_signature1 += '0000000000000000000000000000000000000000000000000000000000000041' + evm_signature[2:]
    result_signature1 += '00000000000000000000000000000000000000000000000000000000000000'
    result_signature2 = encode_data + merkle_root_result['data'][1]['merkleProof'][0][2:]
    result_signature2 += '0000000000000000000000000000000000000000000000000000000000000041' + evm_signature[2:]
    result_signature2 += '00000000000000000000000000000000000000000000000000000000000000'
    return result_signature1, result_signature2


def daily_check_in(address, key, mac_key, device_id, token):
    session = requests.session()
    account = Account.from_key(key)
    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'zh-CN,zh;q=0.9',
        'authorization': f'Bearer {token}',
        'cache-control': 'no-cache',
        # 'content-length': '0',
        'origin': 'https://pioneer.particle.network',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'referer': 'https://pioneer.particle.network/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    }

    random_str, timestamp = str(uuid.uuid4()), int(time.time())
    mac_info = {"timestamp": timestamp, "random_str": random_str,
                "device_id": device_id, "sdk_version": "web_1.0.0",
                "project_uuid": project_uuid,
                "project_client_key": project_client_key,
                "project_app_uuid": project_app_uuid,
                "mac_key": mac_key}
    params = {
        'timestamp': timestamp,
        'random_str': random_str,
        'device_id': device_id,
        'sdk_version': 'web_1.0.0',
        'project_uuid': project_uuid,
        'project_client_key': project_client_key,
        'project_app_uuid': project_app_uuid,
        'mac': sha256(dict(sorted(mac_info.items())))
    }

    response = session.post('https://pioneer-api.particle.network/streaks/streak_tx', params=params,
                            headers=headers).json()
    logger.debug(response)

    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'zh-CN,zh;q=0.9',
        'auth-type': 'None',
        'cache-control': 'no-cache',
        'content-type': 'application/json',
        'origin': 'https://pioneer.particle.network',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'referer': 'https://pioneer.particle.network/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    }

    json_data = {'jsonrpc': '2.0', 'chainId': 11155420, 'method': 'universal_createCrossChainUserOperation', 'params': [
        {'name': 'UNIVERSAL', 'version': '1.0.0', 'ownerAddress': response['smartAccount']['ownerAddress']},
        [{'to': response['tx']['to'], 'data': response['tx']['data'], 'chainId': response['tx']['chainId']}]]}

    response = session.post('https://universal-api.particle.network/', headers=headers, json=json_data).json()
    logger.debug(response)
    user_ops = response['result']['userOps']
    headers = {
        'accept': '*/*',
        'accept-language': 'zh-CN,zh;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/json',
        'origin': 'https://pioneer.particle.network',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'referer': 'https://pioneer.particle.network/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    }

    params = {'chainId': '11155420', 'projectUuid': project_uuid, 'projectKey': project_client_key}
    timestamp = int(time.time())
    json_data = {'jsonrpc': '2.0', 'id': 0, 'method': 'particle_aa_createMultiChainUnsignedData',
                 'params': [{'name': 'UNIVERSAL', 'version': '1.0.0', 'ownerAddress': address, }, {
                     'multiChainConfigs': [{'chainId': user_ops[0]['chainId'], 'userOpHash': user_ops[0]['userOpHash'],
                                            'validUntil': timestamp + 600, 'validAfter': timestamp - 600, },
                                           {'chainId': user_ops[1]['chainId'], 'userOpHash': user_ops[1]['userOpHash'],
                                            'validUntil': timestamp + 600, 'validAfter': timestamp - 600}]}]}

    response = session.post('https://rpc.particle.network/evm-chain', params=params, headers=headers,
                            json=json_data).json()
    logger.debug(response)
    merkle_root = response['result']['merkleRoot']
    evm_signature = account.sign_message(encode_defunct(hexstr=merkle_root)).signature.hex()
    signature1, signature2 = get_signature(response['result'], user_ops[0]['userOp']['signature'], evm_signature)
    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'zh-CN,zh;q=0.9',
        'auth-type': 'None',
        'cache-control': 'no-cache',
        'content-type': 'application/json',
        'origin': 'https://pioneer.particle.network',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'referer': 'https://pioneer.particle.network/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    }

    json_data = {'jsonrpc': '2.0', 'chainId': 11155420, 'method': 'universal_sendCrossChainUserOperation',
                 'params': [[{
                     'sender': user_ops[0]['userOp']['sender'], 'nonce': user_ops[0]['userOp']['nonce'],
                     'initCode': user_ops[0]['userOp']['initCode'], 'callData': user_ops[0]['userOp']['callData'],
                     'paymasterAndData': user_ops[0]['userOp']['paymasterAndData'], 'signature': signature1,
                     'preVerificationGas': user_ops[0]['userOp']['preVerificationGas'],
                     'verificationGasLimit': user_ops[0]['userOp']['verificationGasLimit'],
                     'callGasLimit': user_ops[0]['userOp']['callGasLimit'],
                     'maxFeePerGas': user_ops[0]['userOp']['maxFeePerGas'],
                     'maxPriorityFeePerGas': user_ops[0]['userOp']['maxPriorityFeePerGas'],
                     'chainId': user_ops[0]['chainId']},
                     {'sender': user_ops[1]['userOp']['sender'], 'nonce': user_ops[1]['userOp']['nonce'],
                      'initCode': user_ops[1]['userOp']['initCode'], 'callData': user_ops[1]['userOp']['callData'],
                      'callGasLimit': user_ops[1]['userOp']['callGasLimit'],
                      'verificationGasLimit': user_ops[1]['userOp']['verificationGasLimit'],
                      'preVerificationGas': user_ops[1]['userOp']['preVerificationGas'],
                      'maxFeePerGas': user_ops[1]['userOp']['maxFeePerGas'],
                      'maxPriorityFeePerGas': user_ops[1]['userOp']['maxPriorityFeePerGas'],
                      'paymasterAndData': user_ops[1]['userOp']['paymasterAndData'], 'chainId': user_ops[1]['chainId'],
                      'signature': signature2}]]}

    response = session.post('https://universal-api.particle.network/', headers=headers, json=json_data).json()
    logger.debug(response)

    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'zh-CN,zh;q=0.9',
        'authorization': f'Bearer {token}',
        'origin': 'https://pioneer.particle.network',
        'pragma': 'no-cache',
        'priority': 'u=1, i',
        'referer': 'https://pioneer.particle.network/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    }

    random_str, timestamp = str(uuid.uuid4()), int(time.time())
    mac_info = {"timestamp": timestamp, "random_str": random_str,
                "device_id": device_id, "sdk_version": "web_1.0.0",
                "project_uuid": project_uuid,
                "project_client_key": project_client_key,
                "project_app_uuid": project_app_uuid,
                "mac_key": mac_key}
    params = {
        'timestamp': timestamp,
        'random_str': random_str,
        'device_id': device_id,
        'sdk_version': 'web_1.0.0',
        'project_uuid': project_uuid,
        'project_client_key': project_client_key,
        'project_app_uuid': project_app_uuid,
        'mac': sha256(dict(sorted(mac_info.items())))
    }

    response = session.post('https://pioneer-api.particle.network/users/check_tx_point', params=params,
                            headers=headers).json()
    logger.debug(response)
    random_str, timestamp = str(uuid.uuid4()), int(time.time())
    mac_info = {"timestamp": timestamp, "random_str": random_str,
                "device_id": device_id, "sdk_version": "web_1.0.0",
                "project_uuid": project_uuid,
                "project_client_key": project_client_key,
                "project_app_uuid": project_app_uuid,
                "mac_key": mac_key}
    params = {
        'timestamp': timestamp,
        'random_str': random_str,
        'device_id': device_id,
        'sdk_version': 'web_1.0.0',
        'project_uuid': project_uuid,
        'project_client_key': project_client_key,
        'project_app_uuid': project_app_uuid,
        'mac': sha256(dict(sorted(mac_info.items())))
    }
    response = session.post('https://pioneer-api.particle.network/streaks/check_streak', params=params,
                            headers=headers).json()

    logger.debug(response)
    random_str, timestamp = str(uuid.uuid4()), int(time.time())
    mac_info = {"timestamp": timestamp, "random_str": random_str,
                "device_id": device_id, "sdk_version": "web_1.0.0",
                "project_uuid": project_uuid,
                "project_client_key": project_client_key,
                "project_app_uuid": project_app_uuid,
                "mac_key": mac_key}
    params = {
        'timestamp': timestamp,
        'random_str': random_str,
        'device_id': device_id,
        'sdk_version': 'web_1.0.0',
        'project_uuid': project_uuid,
        'project_client_key': project_client_key,
        'project_app_uuid': project_app_uuid,
        'mac': sha256(dict(sorted(mac_info.items())))
    }
    response = session.get('https://pioneer-api.particle.network/streaks/daily_point', params=params,
                           headers=headers).json()

    logger.debug(response)


if __name__ == '__main__':
    register('****************************', '***********************')
