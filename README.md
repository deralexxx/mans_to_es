# mans_to_es
[![Version](https://img.shields.io/pypi/v/mans_to_es.svg)](https://pypi.python.org/pypi/mans_to_es)


Parses the FireEye HX .mans triage collections and send them to ElasticSearch

## Table of Contents
1. [About](#about)
2. [Getting started](#getting-started)
3. [Disclaimer](#disclaimer)

## About 
mans_to_es is an open source tool for parsing FireEye HX .mans triage collections and send them to ElasticSearch.

Mans file is a zipped collection of xml that we parse using [xmltodict](https://github.com/martinblech/xmltodict).
It uses pandas and multiprocessing to speed up the parsing with xml files.

## Getting started
#### Installation
```
pip install mans_to_es
```

#### Usage

```
usage: MANS to ES [-h] [--filename FILENAME] [--name NAME] [--index INDEX]
                  [--es_host ES_HOST] [--es_port ES_PORT]
                  [--cpu_count CPU_COUNT] [--bulk_size BULK_SIZE] [--version]
agaravaglia@timesketch:~$ python3 /usr/local/bin/mans_to_es.py --help
usage: MANS to ES [-h] [--filename FILENAME] [--name NAME] [--index INDEX]
                  [--es_host ES_HOST] [--es_port ES_PORT]
                  [--cpu_count CPU_COUNT] [--bulk_size BULK_SIZE] [--version]

Push .mans information in Elasticsearch index

optional arguments:
  -h, --help            show this help message and exit
  --filename FILENAME   Path of the .mans file
  --name NAME           Timeline name
  --index INDEX         ES index name
  --es_host ES_HOST     ES host
  --es_port ES_PORT     ES port
  --cpu_count CPU_COUNT
                        cpu count
  --bulk_size BULK_SIZE
                        Bulk size for multiprocessing parsing and upload
  --version             show program's version number and exit

```



## Disclaimer
This is not an official FireEye product. Bugs are expected. 
