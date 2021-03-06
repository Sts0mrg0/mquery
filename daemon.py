#!/usr/bin/env python
import json
import logging
import time

import yara
import plyara
from yara import SyntaxError

import config
from lib.ursadb import UrsaDb
from lib.yaraparse import YaraParser
from util import make_redis, setup_logging

redis = make_redis()
db = UrsaDb(config.BACKEND)


def job_daemon():
    setup_logging()
    logging.info('Daemon running...')

    for extractor in config.METADATA_EXTRACTORS:
        extractor.set_redis(redis)

    while True:
        queue, data = redis.blpop(['queue-search', 'queue-index', 'queue-metadata', 'queue-yara'])

        if queue == 'queue-search':
            job_hash = data
            logging.info('New task: {}:{}'.format(queue, job_hash))

            try:
                execute_search(job_hash)
            except Exception as e:
                logging.exception('Failed to execute job.')
                redis.hmset(job_hash, {
                    'status': 'failed',
                    'error': str(e),
                })
        elif queue == 'queue-yara':
            job_hash, file_path = data.split(':', 1)
            execute_yara(job_hash, file_path)
        elif queue == 'queue-index':
            path = data
            db.index(path)
        elif queue == 'queue-metadata':
            job_hash, file_path = data.split(':', 1)
            execute_metadata(job_hash, file_path)


def execute_metadata(job_hash, file_path):
    if redis.hget('job:' + job_hash, 'status') == 'cancelled':
        return

    current_meta = {}

    for extractor in config.METADATA_EXTRACTORS:
        extr_name = extractor.__class__.__name__
        local_meta = {}
        deps = extractor.__depends_on__

        for dep in deps:
            if dep not in current_meta:
                raise RuntimeError('Configuration problem {} depends on {} but is declared earlier in config.'
                                   .format(extr_name, dep))

            # we build local dictionary for each extractor, thus enforcing dependencies to be declared correctly
            local_meta.update(current_meta[dep])

        current_meta[extr_name] = extractor.extract(file_path, local_meta)

    # flatten
    flat_meta = {}

    for v in current_meta.values():
        flat_meta.update(v)

    logging.info('Fetched metadata: ' + file_path)

    pipe = redis.pipeline()
    pipe.sadd('meta:{}'.format(job_hash), json.dumps({"file": file_path, "meta": flat_meta}))
    pipe.hget('job:{}'.format(job_hash), 'total_files')
    pipe.hincrby('job:{}'.format(job_hash), 'files_processed')
    _, total_files, files_processed = pipe.execute()

    if int(files_processed) >= int(total_files):
        redis.hset('job:{}'.format(job_hash), 'status', 'done')


def execute_yara(job_hash, file):
    if redis.hget('job:' + job_hash, 'status') == 'cancelled':
        return

    job = redis.hgetall('job:' + job_hash)

    logging.info('Compiling Yara')
    yara_rule = job['raw_yara']

    try:
        rule = yara.compile(source=yara_rule)
    except SyntaxError as e:
        logging.exception('Yara parse error')
        raise e

    try:
        matches = rule.match(data=open(file, 'rb').read())
    except yara.Error:
        logging.exception('Yara failed to check file {}'.format(file))
        matches = None
    except FileNotFoundError:
        logging.exception('Failed to open file for yara check: {}'.format(file))
        matches = None

    if matches:
        logging.info('Processed (match): {}'.format(file))
        redis.sadd('matches:' + job_hash, file)
        redis.rpush('queue-metadata', '{}:{}'.format(job_hash, file))
    else:
        logging.info('Processed (nope ): {}'.format(file))

        pipe = redis.pipeline()
        pipe.sadd('false_positives:' + job_hash, file)
        pipe.hget('job:{}'.format(job_hash), 'total_files')
        pipe.hincrby('job:{}'.format(job_hash), 'files_processed')
        _, total_files, files_processed = pipe.execute()

        if int(files_processed) >= int(total_files):
            redis.hset('job:{}'.format(job_hash), 'status', 'done')


def execute_search(job_hash):
    logging.info('Parsing...')

    job = redis.hgetall('job:' + job_hash)
    yara_rule = job['raw_yara']

    redis.hmset('job:' + job_hash, {
        'status': 'parsing',
        'timestamp': time.time(),
    })

    try:
        rules = plyara.Plyara().parse_string(yara_rule)
        parser = YaraParser(rules[0])
        parsed = parser.parse()
    except Exception as e:
        logging.exception(e)
        raise RuntimeError('Failed to parse Yara')

    redis.hmset('job:' + job_hash, {
        'status': 'querying',
        'timestamp': time.time(),
    })

    logging.info('Querying backend...')
    result = db.query(parsed)
    if 'error' in result:
        raise RuntimeError(result['error'])

    job = redis.hgetall(job_hash)
    files = [f for f in result['files'] if f.strip()]

    logging.info('Database responded with {} files'.format(len(files)))

    if 'max_files' in job and int(job['max_files']) > 0:
        files = files[:int(job['max_files'])]

    redis.hmset('job:' + job_hash, {
        'status': 'processing',
        'files_processed': 0,
        'total_files': len(files)
    })

    pipe = redis.pipeline()

    for file in files:
        pipe.rpush('queue-yara', '{}:{}'.format(job_hash, file))

    pipe.execute()
    logging.info('Done uploading yara jobs.')


if __name__ == '__main__':
    job_daemon()
