#! /usr/bin/python
#! /usr/bin/python3

import requests
import json
import base64
import os
import logging
import traceback

from datetime import datetime

#### Configure logger ##########################################
logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
#################################################################

BASE_URL = 'http://gateway.prd.cnj.cloud/autoridades-certificadoras'
BASE_DIR = os.path.dirname(__file__)

def get_date():

    return datetime.now().strftime("%Y-%m-%d")


def get_today_info():

    route = '/api/v1/meta-dados/atualizacao/'
    date = get_date()
    
    try:
        logger.info(f'Resquests: {BASE_URL + route + date}')
        response = requests.get(BASE_URL + route + date)
        if response.status_code == 200:
            logger.info(f'GET {BASE_URL + route + date} return status code: {response.status_code}')
            doc = json.loads(response.text)
            return doc
        else:
            logger.error(f'GET {BASE_URL + route + date} return status code: {response.status_code}')
    except requests.exceptions.HTTPError as err:
        logger.error(err)
        raise SystemExit(err)

def verify_update(doc, **kwargs):

    try:
    
        updated = False

        hash = doc['result']['checksum'+f'{kwargs["cert_type"].capitalize()}']
        hash_file = f'{kwargs["cert_type"]}_hash.txt'
        
        with open(f"{BASE_DIR}/{hash_file}", 'r+') as f:
   
            current_hash = f.read()
    
            if current_hash == hash:

                logger.info(f'No update avaiable for: {kwargs["cert_type"].capitalize()}')
                return updated

            else:
                
                logger.info(f'Update avaiable for: {kwargs["cert_type"].capitalize()}')
                logger.info(f'New hash: {hash}')
                f.seek(0)
                f.truncate()
                f.write(hash)
                logger.info(f'New hash stored in: {hash_file}')
                updated = True
                return updated

    except FileNotFoundError as err:
        logger.error(traceback.format_exc())
        raise SystemExit(err)
    except TypeError as err:
        logger.error(traceback.format_exc())
        raise SystemExit(1)



def get_certs_info(**kwargs):

    route = f"/api/v1/binarios/{kwargs['cert_type']}/"
    hash_file = f"{kwargs['cert_type']}_hash.txt"

    try:
        with open(f"{BASE_DIR}/{hash_file}", 'r+') as f:

            hash = f.read()
        
        response = requests.get(BASE_URL + route + hash)
        logger.info(f'Getting certs info for {get_date()} - Has: {hash}')
        logger.info(f'Requesting: {BASE_URL + route + hash}')

        if response.status_code == 200:
            logger.info(f'GET {BASE_URL + route + hash} return status code: {response.status_code}')
            doc = json.loads(response.text)
            return doc
        else:
            logger.info(f'GET {BASE_URL + route + hash} return status code: {response.status_code}')
            
    except FileNotFoundError as err:
        logger.error(err)
        raise SystemExit(err)
    except requests.exceptions.HTTPError as err:
        logger.error(err)
        raise SystemExit(err)

def generate_files(**kwargs):

    autoridades_certificadoras_dir = BASE_DIR + \
        '/autoridades_certificadoras/' + f"{kwargs['cert_type']}"
    file_base_name = f"{autoridades_certificadoras_dir}/{kwargs['info']['result']['fileName']}"

    try:
        with open(f"{file_base_name}", "wb") as _zip:
            _zip.write(base64.b64decode(kwargs['info']['result']['contentBase64']))

        logger.info(f'Create file: {file_base_name}')    
        files_sufix = ['.hash', '.hash.codec',
                    '.hash.signed', '.hash.signed.algorithm']
        files = [f"{file_base_name}" + file_sufix for file_sufix in files_sufix]

        with open(f"{files[0]}", "w+") as _zipHash, open(f"{files[1]}", "w+") as _zipCodec, open(f"{files[2]}", "w+") as _zipSign, open(f"{files[3]}", "w+") as _zipAlg:
            _zipHash.write(kwargs['update_info']['result']
                        ['checksum'+f'{kwargs["cert_type"].capitalize()}'])
            logger.info(f'Create file: {files[0]}')    

            _zipCodec.write(kwargs['info']['result']['checksumCodec'])
            logger.info(f'Create file: {files[1]}')
            
            _zipSign.write(kwargs['info']['result']['signedChecksum'])
            logger.info(f'Create file: {files[2]}')

            _zipAlg.write(kwargs['info']['result']['signatureAlgorithm'])
            logger.info(f'Create file: {files[3]}')
        
        return True
    
    except IOError as err:
        logger.error('Cannot create files: See error output.')
        raise SystemExit(err)


if __name__ == "__main__":

    logger.info('Starting update proccess...')
    logger.info(f'Setup base URL as: {BASE_URL}')
    logger.info(f'Setup Working dir as: {BASE_DIR}')
    
    certs = ['intermediarias', 'confiaveis']

    logger.info(f'Getting info for: {get_date()}')

    update_info = get_today_info()

    # verify_update(update_info, cert_type='intermediarias')
    for cert_type in certs:

        if verify_update(update_info, cert_type=cert_type):

            logger.info(f"Updating {cert_type.capitalize()}.....")       
            logger.info(f'New  {cert_type.capitalize()} info found...')
            logger.info(f'Generating new files for: {cert_type.capitalize()}')

            if generate_files(info=get_certs_info(
                cert_type=cert_type), update_info=update_info, cert_type=cert_type):
                
                logger.info(f"{cert_type.capitalize()} files created!")

                with open('last_update.txt', 'w+') as f:
                    f.write(get_date())
                
            logger.info(f"{cert_type.capitalize()} UPDATED - {get_date()}")
        else:
            logger.info(f"{cert_type.capitalize()} not updated")
