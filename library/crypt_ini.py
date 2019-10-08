#!/usr/bin/python

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: crypt_ini

short_description: Change password in encrypted ini file

version_added: "2.4"

description:
    - "Change password in encrypted ini file"

options:
    path:
        description:
            - This is the path of encrypted file
        required: true
    passw:
        description:
            - This is the password of encrypted file
        required: false
    key:
        description:
            - This is the key for password change
        required: true
    key_passw:
        description:
            - This is the key for password change
        required: false
    silent:
        description:
            - Silent mode
        required: false

author:
    - Shukalov Aleksandr (shukalov@bk.ru)
'''

EXAMPLES = '''
# Pass in a message
- name: Test with a file
  crypt_ini:
    path: /tmp/encr.file
    passw: mypasw
    key: user1
    key_passw: user1_passw
    silent: True

'''

RETURN = '''
original_message:
    description: The original name param that was passed in
    type: str
    returned: always
message:
    description: The output message that the crypt_ini module generates
    type: str
    returned: always
'''


from ansible.module_utils.basic import AnsibleModule

import string
import tempfile
import io
import os, random, struct
import configparser

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2


def encrypt_file(passw, in_file, out_file):

    salt = b'my_salt'
    key = PBKDF2(passw, salt, dkLen=32)
    chunk_size = 64*1024

    iv = Random.new().read(AES.block_size)

    #create the encryption cipher
    encryptor = AES.new(key, AES.MODE_CBC, iv)

    #Determine the size of the file
    filesize = os.path.getsize(in_file)

    #Open the output file and write the size of the file.
    #We use the struct package for the purpose.
    with open(in_file, 'rb') as inputfile:
        with open(out_file, 'wb') as outputfile:
            outputfile.write(struct.pack('<Q', filesize))
            outputfile.write(iv)

            while True:
                chunk = inputfile.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)
                outputfile.write(encryptor.encrypt(chunk))


def decrypt_file(passw, in_file, out_file=None, chunksize=24*1024):

    salt = b'my_salt'
    key = PBKDF2(passw, salt, dkLen=32)

    with open(in_file, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]

        iv = infile.read(AES.block_size)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        if out_file:
            with open(out_file, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptor.decrypt(chunk))

                outfile.truncate(origsize)
        else:

            f = io.BytesIO()

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                f.write(decryptor.decrypt(chunk))

            f.truncate(origsize)

            return f


def run_module():
    module_args = dict(
        path=dict(type='str', required=True),
        passw=dict(type='str', required=False, default=False),
        key=dict(type='str', required=True),
        key_passw=dict(type='str', required=False, default=''.join(random.choice(string.ascii_letters + string.digits) for i in range(16))),
        silent=dict(type='bool', required=False, default=True)
    )

    result = dict(
        changed=False,
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    f = io.BytesIO()

    try:
        f = decrypt_file(module.params['passw'], module.params['path'])
    except Exception as e:
        module.fail_json(msg='File decryption fail ({})'.format(str(e)), **result)


    try:

        config = configparser.ConfigParser()
        config.read_string(f.getvalue().decode('UTF-8'))

        old_key_passw = config.get('Users', module.params['key'])

    except Exception as e:
        module.fail_json(msg='File structure incorrect ({})'.format(str(e)), **result)

    if module.params['key_passw'] != old_key_passw:
        result['changed'] = True
        config.set('Users', module.params['key'], module.params['key_passw'])

        with tempfile.TemporaryDirectory() as tmpdirname:
            with open(os.path.join(tmpdirname, 'tmpfile'), 'w') as configfile:
                config.write(configfile)

            encrypt_file(module.params['passw'], os.path.join(tmpdirname, 'tmpfile'), module.params['path'])

    if not module.params['silent']:
        result['original_message'] = 'In file={} with pass={} change for key={} to new_pasw={}'.format(module.params['path'], module.params['passw'], module.params['key'], module.params['key_passw'])
        if result['changed']:
            result['message'] = 'Old_password={}, new_passw={}'.format(old_key_passw, module.params['key_passw'])


    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()