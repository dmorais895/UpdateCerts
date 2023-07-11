import requests
import json
import base64
import os
import logging

from datetime import datetime

BASE_URL = 'http://gateway.prd.cnj.cloud/autoridades-certificadoras'
BASE_DIR = os.path.dirname(__file__)

def get_date():

    return datetime.now().strftime("%Y-%m-%d")


def get_today_info():

    route = '/api/v1/meta-dados/atualizacao/'
    date = get_date()
    
    try:
        response = requests.get(BASE_URL + route + date)
        if response.status_code == 200:
            doc = json.loads(response.text)
            return doc
        else:
            print(f'Service returns status code: {response.status_code}')
    except requests.exceptions.HTTPError as err:
        raise SystemExit(err)

def verify_update(doc, **kwargs):

    updated = False

    hash = doc['result']['checksum'+f'{kwargs["cert_type"].capitalize()}']
    hash_file = f'{kwargs["cert_type"]}_hash.txt'
    
    try:
        with open(f"{BASE_DIR}/{hash_file}", 'r+') as f:
   
            current_hash = f.read()
    
            if current_hash == hash:

                return updated

            else:

                f.seek(0)
                f.truncate()
                f.write(hash)
                updated = True
                return updated

    except FileNotFoundError as err:
        SystemExit(err)



def get_certs_info(**kwargs):

    route = f"/api/v1/binarios/{kwargs['cert_type']}/"
    hash_file = f"{kwargs['cert_type']}_hash.txt"

    try:
        with open(f"{BASE_DIR}/{hash_file}", 'r+') as f:

            hash = f.read()
            
        response = requests.get(BASE_URL + route + hash)
        if response.status_code == 200:
            doc = json.loads(response.text)
            return doc
        else:
            print(f'Service returns status code: {response.status_code}')
            return 1
            
    except FileNotFoundError as err:
        raise SystemExit(err)
    except requests.exceptions.HTTPError as err:
        raise SystemExit(err)

def generate_files(**kwargs):

    autoridades_certificadoras_dir = BASE_DIR + \
        '/autoridades_certificadoras/' + f"{kwargs['cert_type']}"
    file_base_name = f"{autoridades_certificadoras_dir}/{kwargs['info']['result']['fileName']}"

    try:
        with open(f"{file_base_name}", "wb") as _zip:
            _zip.write(base64.b64decode(kwargs['info']['result']['contentBase64']))

        files_sufix = ['.hash', '.hash.codec',
                    '.hash.signed', '.hash.signed.algorithm']
        files = [f"{file_base_name}" + file_sufix for file_sufix in files_sufix]

        with open(f"{files[0]}", "w+") as _zipHash, open(f"{files[1]}", "w+") as _zipCodec, open(f"{files[2]}", "w+") as _zipSign, open(f"{files[3]}", "w+") as _zipAlg:
            _zipHash.write(kwargs['update_info']['result']
                        ['checksum'+f'{kwargs["cert_type"].capitalize()}'])
            _zipCodec.write(kwargs['info']['result']['checksumCodec'])
            _zipSign.write(kwargs['info']['result']['signedChecksum'])
            _zipAlg.write(kwargs['info']['result']['signatureAlgorithm'])
    except IOError as err:
        raise SystemExit(err)


if __name__ == "__main__":

    certs = ['intermediarias', 'confiaveis']

    update_info = get_today_info()

    # verify_update(update_info, cert_type='intermediarias')
    for cert_type in certs:

        print(f"Updating {cert_type.capitalize()}.....")

        if verify_update(update_info, cert_type=cert_type):
            if generate_files(info=get_certs_info(
                cert_type=cert_type), update_info=update_info, cert_type=cert_type):
                with open('last_update.txt', 'w+') as f:
                    f.write(get_date())
                print(f"{cert_type.capitalize()} UPDATED - {get_date()}")
        else:
            print(f"{cert_type.capitalize()} not updated")
