# application
import os


def env_or_default(key, default):
    return (lambda val: default if val is None else val)(os.environ.get(key))


APP_NAME = 'accounts'
VERSION = 1
WEB_HOST = env_or_default('WEB_HOST', 'localhost')
WEB_PORT = int(env_or_default('WEB_PORT', 5000))

# database

DB_HOST = env_or_default('DB_HOST', 'localhost')
DB_PORT = int(env_or_default('DB_PORT', 27017))

# logging

LOG_GLOBAL = 'global.log'
LOG_SUMMARY = 'summary.log'
