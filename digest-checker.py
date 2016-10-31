import hashlib
import logging
import sys

logger = logging.getLogger('digest-auth')

def parse_authorisation_header(auth):
    """
    Read the entire Authorization header and parse the arguments
    """
    logger.debug('Parse header: %s', auth)

    components = {}

    try:
        parts = auth[len('Authorization: Digest '):].split(',')
        logger.debug(parts)

        for part in parts:
            key, value = part.strip().split('=', 1)
            components[key.lower()] = value.strip("\"'")
    except IndexError as e:
        logger.debug(e)

    logger.debug(components)
    return components


def generate_response(user, password, realm, uri, nonce, nonce_count=1, cnonce=None, directive='MD5', qop='auth', method='REGISTER'):
    """
    Digest Auth response generator
    https://en.wikipedia.org/wiki/Digest_access_authentication
    """
    HA1 = None
    if directive in ('MD5', 'MD5-sess', None):
        HA1 = hashlib.md5('{0}:{1}:{2}'.format(user, realm, password)).hexdigest()

    if directive == 'MD5-sess':
        HA1 = hashlib.md5('{0}:{1}:{2}'.format(HA1, nonce, cnonce)).hexdigest()

    if not HA1:
        raise ValueError('Directive %s is unspecified behaviour'.format(directive))

    logger.debug(HA1)

    if qop in ('auth', None):
        HA2 = hashlib.md5('{0}:{1}'.format(method, uri)).hexdigest()
    elif qop == 'auth-int':
        body_digest = hashlib.md5(body).hexdigest()
        HA2 = hashlib.md5('{0}:{1}:{2}'.format(method, uri, body_digest)).hexdigest()


    logger.debug(HA2)

    if qop in ('auth', 'auth-int') and cnonce:
        logger.debug('QOP %s, use cnonce', qop)
        params = dict(HA1=HA1, nonce=nonce, nc=nonce_count, cnonce=cnonce, qop=qop, HA2=HA2)
        response = hashlib.md5('{HA1}:{nonce}:{nc}:{cnonce}:{qop}:{HA2}'.format(**params)).hexdigest()
    else:
        response = hashlib.md5('{0}:{1}:{2}'.format(HA1, nonce, HA2)).hexdigest()


    logger.debug('Calculated response %s', response)
    return response



if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description='Check the digest authentication is correct'
    )

    parser.add_argument('-l', '--logging', help='logging module log LEVEL, called by logging.getLevelName()', default='INFO')
    parser.add_argument('-p', '--password', help='password to use for generating', action="store", type=str, required=True)
    parser.add_argument('-m', '--method', help='METHOD to be used e.g. GET or REGISTER', action="store", type=str, required=True)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--infile', help='File to read raw authentication from', action='store', type=str)
    group.add_argument('-a', '--auth', help='Full authentication header to parse', action='store', type=str)

    args = parser.parse_args()

    try:
        logging.basicConfig(level=logging.getLevelName(args.logging))
    except TypeError:
        logging.basicConfig(level=logging.INFO)


    if args.infile:
        with open(args.infile, 'r') as auth_file:
            auth = auth_file.read()
    elif args.auth:
        auth = args.auth
    
    params = parse_authorisation_header(auth)

    response = generate_response(
        user=params.get('username'),
        password=args.password,
        realm=params.get('realm'),
        uri=params.get('uri'),
        nonce=params.get('nonce'),
        nonce_count=params.get('nc'),
        cnonce=params.get('cnonce'),
        qop=params.get('qop'),
        method=args.method,
        directive=params.get('algorithm'),
    ) 

    logger.info('Generated Digest response is %s', response)
    logger.info('Response from auth header is %s', params.get('response'))
