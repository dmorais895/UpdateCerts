import requests
import json
import base64
import os

from datetime import datetime

BASE_URL = 'http://gateway.prd.cnj.cloud/autoridades-certificadoras'
BASE_DIR = os.path.dirname(__file__)


def get_date():

    return datetime.now().strftime("%Y-%m-%d")


def get_today_info():
    route = '/api/v1/meta-dados/atualizacao/'
    date = get_date()
    response = requests.get(BASE_URL + route + date)
    if response.status_code == 200:
        doc = json.loads(response.text)
        return doc
    else:
        print(f'Service returns status code: {response.status_code}')


def verify_update(doc, **kwargs):

    updated = False

    if kwargs['cert_type'] == 'intermediarias':
        hash = doc['result']['checksumIntermediarias']
        hash_file = 'intermediarias_hash.txt'
    else:
        hash = doc['result']['checksumConfiaveis']
        hash_file = 'confiaveis_hash.txt'

    f = open(f"{hash_file}", 'r+')

    current_hash = f.read()
    print(current_hash)

    if current_hash == hash:

        f.close()
        return updated

    else:

        f.seek(0)
        f.truncate()
        f.write(hash)
        f.close()
        updated = True
        return updated


def get_certs_info(**kwargs):

    route = f"/api/v1/binarios/{kwargs['cert_type']}/"
    hash_file = f"{kwargs['cert_type']}_hash.txt"
    print(route)
    print(hash_file)
    f = open(f"{hash_file}", "r+")

    hash = f.read()

    response = requests.get(BASE_URL + route + hash)
    if response.status_code == 200:
        doc = json.loads(response.text)
        return doc
    else:
        print(f'Service returns status code: {response.status_code}')
        return 1


def convert_base64_to_file(**kwargs):

    autoridades_certificadoras_dir = BASE_DIR + '/autoridades_certificadoras'
    file_base_name = f"{autoridades_certificadoras_dir}/{kwargs['info']['result']['fileName']}"
    print(kwargs['update_info']['result']['checksumIntermediarias'])
    with open(f"{file_base_name}", "wb") as _zip: 
        _zip.write(base64.b64decode(kwargs['info']['result']['contentBase64']))

    files_sufix = ['.hash', '.hash.codec', '.hash.signed', '.hash.signed.algorithm']
    files = [ f"{file_base_name}" + file_sufix for file_sufix in files_sufix]

    print(files)

    # with open(f"{file_base_name}.hash", "w+") as _zipHash, open(f"{file_base_name}.hash.codec", "w+") as _zipCodec:
    #     _zipHash.write(kwargs['update_info']['result']
    #                    ['checksumIntermediarias'])
    #     _zipCodec.write(kwargs['info']['result']['checksumCodec'])
    # # print(kwargs['info']['result']['fileName'])


if __name__ == "__main__":

    print("Update Intermediarias")

    update_info = get_today_info()

    if verify_update(update_info, cert_type='intermediarias'):
        info = get_certs_info(cert_type='intermediarias')
        convert_base64_to_file(info=info, update_info=update_info)
        # print(info)
    else:
        print("Intermediarias not updated")
    # print(os.path.dirname(__file__))
