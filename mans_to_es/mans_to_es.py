#!/usr/bin/env python3
import argparse
import collections
import functools
import json
import logging
import operator
import os
import sys
import xml.etree.cElementTree as ET
import zipfile
from multiprocessing import cpu_count, Pool

import ciso8601
import pandas as pd
import xmltodict
from elasticsearch import helpers, Elasticsearch

# hide ES log
es_logger = logging.getLogger("elasticsearch")
es_logger.setLevel(logging.ERROR)
url_logger = logging.getLogger("urllib3")
url_logger.setLevel(logging.ERROR)

FORMAT = "%(asctime)-15s %(message)s"
logging.basicConfig(filename="mans_to_es.log", level=logging.DEBUG, format=FORMAT)

type_name = {
    "persistence": {
        "key": "PersistenceItem",
        "keys": [
            "PersistenceType",
            "RegPath",
            "RegText",
            "RegOwner",
            "RegModified",
            "FilePath",
            "FileOwner",
            "FileCreated",
            "FileModified",
            "FileAccessed",
            "FileChanged",
            "SignatureExists",
            "SignatureVerified",
            "SignatureDescription",
            "CertificateSubject",
            "CertificateIssuer",
            "md5sum",
            "FileItem",
            "RegistryItem",
            "RegContext",
            "RegValue",
            "ServicePath",
            "ServiceName",
            "descriptiveName",
            "arguments",
            "mode",
            "startedAs",
            "status",
            "pathSignatureExists",
            "pathSignatureVerified",
            "pathSignatureDescription",
            "pathCertificateSubject",
            "pathCertificateIssuer",
            "pathmd5sum",
            "ServiceItem",
            "serviceDLL",
            "serviceDLLSignatureExists",
            "serviceDLLSignatureVerified",
            "serviceDLLSignatureDescription",
            "serviceDLLCertificateSubject",
            "serviceDLLCertificateIssuer",
            "serviceDLLmd5sum",
            "LinkFilePath",
        ],
        "datefields": [
            "RegModified",
            "FileCreated",
            "FileModified",
            "FileAccessed",
            "FileChanged",
        ],
        "message_fields": {
            "RegModified": ["RegPath"],
            "FileCreated": ["FilePath"],
            "FileModified": ["FilePath"],
            "FileAccessed": ["FilePath"],
            "FileChanged": ["FilePath"],
        },
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
    },
    "processes-api": {
        "key": "ProcessItem",
        "keys": [
            "pid",
            "parentpid",
            "path",
            "name",
            "arguments",
            "Username",
            "SecurityID",
            "SecurityType",
            "startTime",
            "kernelTime",
            "userTime",
        ],
        "datefields": ["startTime"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {"startTime": ["name"]},
    },
    "processes-memory": {
        "key": "ProcessItem",
        "keys": [
            "pid",
            "parentpid",
            "path",
            "name",
            "arguments",
            "Username",
            "SecurityID",
            "SecurityType",
            "startTime",
            "kernelTime",
            "userTime",
            "HandleList",
            "SectionList",
            "PortList",
        ],
        "datefields": ["startTime"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {"startTime": ["name"]},
    },
    "urlhistory": {
        "key": "UrlHistoryItem",
        "keys": [
            "Profile",
            "BrowserName",
            "BrowserVersion",
            "Username",
            "URL",
            "PageTitle",
            "HostName",
            "Hidden",
            "Typed",
            "LastVisitDate",
            "VisitType",
            "VisitCount",
            "VisitFrom",
            "FirstBookmarkDate",
        ],
        "datefields": ["LastVisitDate"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {"LastVisitDate": ["URL"]},
    },
    "stateagentinspector": {
        "key": "eventItem",
        "keys": ["timestamp", "eventType", "details"],
        "datefields": ["timestamp"],
        "dateformat": "%Y-%m-%dT%H:%M:%S.%fZ",
        "subtypes": {
            "addressNotificationEvent": {
                "meta": ["address"],
                "message_fields": ["address"],
            },
            "regKeyEvent": {
                "meta": [
                    "hive",
                    "keyPath",
                    "path",
                    "pid",
                    "process",
                    "processPath",
                    "username",
                ],
                "message_fields": ["keyPath"],
            },
            "ipv4NetworkEvent": {
                "meta": [
                    "localIP",
                    "localPort",
                    "pid",
                    "process",
                    "processPath",
                    "protocol",
                    "remoteIP",
                    "remotePort",
                    "username",
                ],
                "message_fields": ["localIP", "remoteIP"],
                "hits_key": "EXC",
            },
            "processEvent": {
                "meta": [
                    "md5",
                    "parentPid",
                    "parentProcess",
                    "parentProcessPath",
                    "pid",
                    "process",
                    "processCmdLine",
                    "processPath",
                    "startTime",
                    "username",
                    "eventType",
                ],
                "message_fields": ["process", "eventType"],
                "hits_key": "EXC",
            },
            "imageLoadEvent": {
                "meta": [
                    "devicePath",
                    "drive",
                    "fileExtension",
                    "fileName",
                    "filePath",
                    "fullPath",
                    "pid",
                    "process",
                    "processPath",
                    "username",
                ],
                "message_fields": ["fileName"],
            },
            "fileWriteEvent": {
                "meta": [
                    "closed",
                    "dataAtLowestOffset",
                    "devicePath",
                    "drive",
                    "fileExtension",
                    "fileName",
                    "filePath",
                    "fullPath",
                    "lowestFileOffsetSeen",
                    "md5",
                    "numBytesSeenWritten",
                    "pid",
                    "process",
                    "processPath",
                    "size",
                    "textAtLowestOffset",
                    "username",
                    "writes",
                ],
                "message_fields": ["fileName"],
                "hits_key": "PRE",
            },
            "dnsLookupEvent": {
                "meta": ["hostname", "pid", "process", "processPath", "username"],
                "message_fields": ["hostname"],
            },
            "urlMonitorEvent": {
                "meta": [
                    "hostname",
                    "requestUrl",
                    "urlMethod",
                    "userAgent",
                    "httpHeader",
                    "remoteIpAddress",
                    "remotePort",
                    "localPort",
                    "pid",
                    "process",
                    "processPath",
                    "username",
                ],
                "message_fields": ["requestUrl"],
            },
        },
    },
    "prefetch": {
        "key": "PrefetchItem",
        "keys": [
            "FullPath",
            "Created",
            "SizeInBytes",
            "PrefetchHash",
            "ReportedSizeInBytes",
            "ApplicationFileName",
            "LastRun",
            "TimesExecuted",
            "AccessedFileList",
            "ApplicationFullPath",
            "VolumeList",
        ],
        "datefields": ["LastRun", "Created"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {
            "LastRun": ["ApplicationFileName"],
            "Created": ["ApplicationFileName"],
        },
    },
    "filedownloadhistory": {
        "key": "FileDownloadHistoryItem",
        "keys": [
            "Profile",
            "BrowserName",
            "BrowserVersion",
            "Username",
            "DownloadType",
            "BytesDownloaded",
            "MaxBytes",
            "SourceURL",
            "TargetDirectory",
            "EndDate",
            "FileName",
            "StartDate",
            "State",
            "CacheHitCount",
            "LastModifiedDate",
            "CacheFlags",
            "LastCheckedDate",
            "FullHttpHeader",
            "LastAccessedDate",
        ],
        "datefields": ["LastModifiedDate", "LastAccessedDate", "StartDate", "EndDate"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {
            "LastModifiedDate": ["SourceURL"],
            "LastAccessedDate": ["SourceURL"],
            "StartDate": ["SourceURL"],
            "EndDate": ["SourceURL"],
        },
    },
    "files-raw": {
        "key": "FileItem",
        "keys": [
            "DevicePath",
            "FullPath",
            "Drive",
            "FileName",
            "Username",
            "SecurityID",
            "SecurityType",
            "SizeInBytes",
            "Created",
            "Modified",
            "Accessed",
            "Changed",
            "FilenameCreated",
            "FilenameModified",
            "FilenameAccessed",
            "FilenameChanged",
            "FileAttributes",
            "INode",
            "Md5sum",
            "StreamList",
            "FilePath",
            "FileExtension",
            "PEInfo",
        ],
        "datefields": ["Created", "Modified", "Accessed", "Changed"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {
            "Created": ["FullPath"],
            "Modified": ["FullPath"],
            "Accessed": ["FullPath"],
            "Changed": ["FullPath"],
        },
    },
    "cookiehistory": {
        "key": "CookieHistoryItem",
        "keys": [
            "Profile",
            "BrowserName",
            "BrowserVersion",
            "Username",
            "HostName",
            "CookiePath",
            "CookieName",
            "CookieValue",
            "IsSecure",
            "IsHttpOnly",
            "LastAccessedDate",
            "ExpirationDate",
            "FileName",
            "LastModifiedDate",
            "FilePath",
            "CreationDate",
            "CookieFlags",
        ],
        "datefields": ["LastAccessedDate", "ExpirationDate"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {
            "LastAccessedDate": ["HostName"],
            "ExpirationDate": ["HostName"],
        },
    },
    "eventlogs": {
        "key": "EventLogItem",
        "keys": [
            "log",
            "source",
            "index",
            "EID",
            "type",
            "genTime",
            "writeTime",
            "machine",
            "message",
            "category",
            "user",
            "ExecutionProcessId",
            "ExecutionThreadId",
            "unformattedMessage",
            "CorrelationActivityId",
        ],
        "datefields": ["genTime"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {"genTime": ["EID", "source", "type"]},
    },
    "registry-raw": {
        "key": "RegistryItem",
        "keys": [
            "Username",
            "SecurityID",
            "Path",
            "Hive",
            "KeyPath",
            "Type",
            "Modified",
            "NumSubKeys",
            "NumValues",
            "ValueName",
            "Text",
            "ReportedLengthInBytes",
            "Value",
            "detectedAnomaly",
        ],
        "datefields": ["Modified"],
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "message_fields": {"Modified": ["KeyPath"]},
    },
    "tasks": {"key": "TaskItem", "skip": True},
    "ports": {"key": "PortItem", "skip": True},
    "useraccounts": {"key": "UserItem", "skip": True},
    "disks": {"key": "DiskItem", "skip": True},
    "volumes": {"key": "VolumeItem", "skip": True},
    "network-dns": {"key": "DnsEntryItem", "skip": True},
    "network-route": {"key": "RouteEntryItem", "skip": True},
    "network-arp": {"key": "ArpEntryItem", "skip": True},
    "sysinfo": {"key": "SystemInfoItem", "skip": True},
    "services": {"key": "ServiceItem", "skip": True},
    "hivelist": {"key": "HiveItem", "skip": True},
    "drivers-modulelist": {"key": "ModuleItem", "skip": True},
    "drivers-signature": {"key": "DriverItem", "skip": True},
    "formhistory": {"key": "FormHistoryItem", "skip": True},
    "kernel-hookdetection": {"key": "HookItem", "skip": True},
}


def generate_df(fo, filetype, uid=False):
    """
        Generate dataframe from xml file
    """
    try:
        _df = []
        tree = ET.parse(fo)
        root = tree.getroot()
        type_dict = type_name[filetype]
        message = filetype
        for PI in root.findall(type_dict["key"]):
            tmp_dict = {}
            if uid:
                tmp_dict["uid"] = PI.attrib["uid"]
            for key in type_dict["keys"]:
                if PI.find(key) is None:
                    tmp_dict[key] = None
                else:
                    if key.endswith("List"):
                        tmp_dict[key] = xmltodict.parse(
                            ET.tostring(PI.find(key), "utf-8", method="xml"),
                            xml_attribs=False,
                        )[key]
                    elif key.endswith("Item"):
                        tmp_dict[key] = xmltodict.parse(
                            ET.tostring(PI.find(key), "utf-8", method="xml"),
                            xml_attribs=False,
                        )[key]
                    else:
                        # stateagent has eventType as key in main xml and also in details subfield
                        if key == "eventType":
                            message = PI.find(key).text
                            tmp_dict["subEvent"] = PI.find(key).text
                        elif key == "details":
                            detail_dict = xmltodict.parse(
                                ET.tostring(PI.find(key), "utf-8", method="xml"),
                                xml_attribs=False,
                            )[key]["detail"]
                            if type(detail_dict) == list:
                                for i in detail_dict:
                                    tmp_dict[i["name"]] = i["value"]
                            elif type(detail_dict) in (collections.OrderedDict, dict):
                                tmp_dict[detail_dict["name"]] = detail_dict["value"]
                        else:
                            tmp_dict[key] = PI.find(key).text
            tmp_dict["message"] = message
            tmp_dict["mainEvent"] = filetype
            _df.append(tmp_dict)
        return pd.DataFrame(_df), True
    except ET.ParseError:
        return None, False


def convert_both(argument):
    """
        convert_both: parse date field and convert to it to proper
        in:
            argument: object to parse
        out:
            parsed data
    """
    try:
        d = ciso8601.parse_datetime(argument)
        return pd.Series(
            [d.isoformat(timespec="seconds"), str(int(d.timestamp() * 1000000))]
        )
    except (ValueError, OSError):
        logging.error("date %s not valid" % str(argument))
        return pd.Series([None, None])


class MansToEs:
    def __init__(self, args):
        self.filename = args.filename
        self.index = args.index
        self.name = args.name
        self.bulk_size = args.bulk_size
        self.cpu_count = args.cpu_count
        self.es_info = {"host": args.es_host, "port": args.es_port}
        self.folder_path = self.filename + "__tmp"
        self.filelist = {}
        self.ioc_alerts = {}
        self.exd_alerts = []

        logging.debug(
            "Start parsing %s. Push on %s index and %s timeline"
            % (args.filename, args.name, args.index)
        )

    def get_hits(self):
        """
            Get hit and alert from hits.json file
        """
        if not os.path.exists(os.path.join(self.folder_path, "hits.json")):
            logging.debug("Hits.json: missing")
        else:
            with open(os.path.join(self.folder_path, "hits.json"), "r") as f:
                for x in json.load(f):
                    if x.get("data", {}).get("key", None):
                        self.ioc_alerts.setdefault(
                            x["data"]["key"]["event_type"], []
                        ).append(str(x["data"]["key"]["event_id"]))
                    elif x.get("data", {}).get("documents", None) or x.get(
                        "data", {}
                    ).get("analysis_details", None):
                        (alert_datetime, alert_timestamp) = convert_both(
                            x["data"]["earliest_detection_time"]
                        )
                        self.exd_alerts.append(
                            {
                                "source": x["source"],
                                "resolution": x["resolution"],
                                "process id": x["data"]["process_id"],
                                "process name": x["data"]["process_name"],
                                "alert_code": "XPL",
                                "datetime": alert_datetime,
                                "timestamp": alert_timestamp,
                                "ALERT": True,
                                "message": "PID: %s PROCESS: %s"
                                % (
                                    str(x["data"]["process_id"]),
                                    x["data"]["process_name"],
                                ),
                            }
                        )
            if len(self.exd_alerts) > 0:
                es = Elasticsearch([self.es_info])
                helpers.bulk(
                    es, self.exd_alerts, index=self.index, doc_type="generic_event"
                )
            logging.debug("Hits.json: parsed")

    def extract_mans(self):
        """
            Unzip .mans file
        """
        zip_ref = zipfile.ZipFile(self.filename, "r")
        zip_ref.extractall(self.folder_path)
        zip_ref.close()
        logging.debug("File extracted in %s" % self.folder_path)

    def parse_manifest(self):
        """
            Obtains filenames from manifest.json file in extracted foldere
        """
        with open(os.path.join(self.folder_path, "manifest.json"), "r") as f:
            data = json.load(f)
            for item in data["audits"]:
                if item["generator"] not in self.filelist.keys():
                    self.filelist[item["generator"]] = []
                for res in item["results"]:
                    if res["type"] == "application/xml":
                        self.filelist[item["generator"]].append(res["payload"])
        logging.debug("Manifest.json: parsed")

    def process(self):
        """
            Process all files contained in .mans extracted folder
        """
        tasks = []
        for filetype in self.filelist.keys():
            # If filetype is new for now it's skipped
            if filetype not in type_name.keys():
                logging.debug("%s: not recognize. Send us a note! - SKIP" % filetype)
                continue
            # Ignore items if not related to timeline
            # TODO: will use them in neo4j for relationship
            if type_name[filetype].get("skip", False):
                logging.debug("%s: SKIP" % filetype)
                continue
            # Read all files related to the type
            for file in self.filelist[filetype]:
                tasks.append((filetype, file))
        with Pool(processes=self.cpu_count) as pool:
            pool.starmap_async(self.process_file, tasks).get()
        logging.debug("COMPLETED")

    def process_file(self, filetype, file):

        info = type_name[filetype]

        logging.debug("%s: %s opening" % (filetype, file))

        df, valid = generate_df(
            open(os.path.join(self.folder_path, file), "r", encoding="utf8"),
            filetype,
            filetype == "stateagentinspector",
        )
        logging.debug("%s: %s df created" % (filetype, file))

        if not valid:
            logging.error("%s: %s -- ERROR DURING XML READ" % (filetype, file))
            return

        # check all date field, if not present remove them, if all not valid skip
        datefields = [x for x in info["datefields"] if x in df.columns]
        if len(datefields) == 0:
            logging.debug("%s: has no valid time field - SKIP" % filetype)
            return

        # if not valid date field drop them
        df = df.dropna(axis=0, how="all", subset=datefields)
        if df.empty:
            logging.debug("%s: has no valid data in time field - SKIP" % filetype)
            return

        # melt multiple date fields
        if len(datefields) > 1:
            df = df.melt(
                id_vars=[x for x in df.columns if x not in datefields],
                var_name="datetype",
                value_name="datetime",
            )
            # some of them could be null - delete them
        else:
            df["datetype"] = datefields[0]
            df = df.rename(columns={datefields[0]: "datetime"})

        df = df[df["datetime"].notnull()]

        # convert datetime to default format
        logging.debug("%s: %s convert date start" % (filetype, file))
        df[["datetime", "timestamp"]] = df["datetime"].apply(lambda x: convert_both(x))
        logging.debug("%s: %s convert date end" % (filetype, file))

        if filetype == "stateagentinspector":

            alert_ids = functools.reduce(
                operator.iconcat, [x for x in self.ioc_alerts.values()], []
            )
            df = df.assign(
                **{
                    "source": None,
                    "resolution": None,
                    "ALERT": None,
                    "alert_code": None,
                }
            )
            df.loc[df["uid"].isin(alert_ids), ["source", "resolution", "ALERT"]] = [
                "IOC",
                "ALERT",
                True,
            ]

            df.loc[df["uid"].isin(alert_ids), "alert_code"] = df.loc[
                df["uid"].isin(alert_ids), "subEvent"
            ].apply(lambda x: info["subtypes"].get(x, {}).get("hits_key", None))

            logging.debug("%s: %s upload start" % (filetype, file))
            # each subtype has different fields and message fields
            for sb in df["subEvent"].unique():

                # if it's new we cannot continue
                if sb not in info["subtypes"].keys():
                    logging.debug(
                        "%s: %s -- new subtype found: %s. Send us a note!"
                        % (filetype, file, sb)
                    )
                    continue

                logging.debug("%s: %s subtype: %s" % (filetype, file, sb))

                # take only valid column for that subtype
                subdf = df[df["subEvent"] == sb].reindex(
                    columns=info["subtypes"][sb]["meta"]
                    + [
                        "message",
                        "datetime",
                        "timestamp_desc",
                        "subEvent",
                        "mainEvent",
                        "datetype",
                        "timestamp",
                    ]
                )

                # add messages based on selected fields value
                if info["subtypes"][sb].get("message_fields", None):
                    subdf["message"] = subdf.apply(
                        lambda row: " - ".join(
                            [row["message"]]
                            + [
                                row[mf]
                                for mf in info["subtypes"][sb]["message_fields"]
                                if row[mf]
                            ]
                        )
                        + " [%s]" % row["datetype"],
                        axis=1,
                    )
                else:
                    subdf["message"] = subdf.apply(
                        lambda row: row["message"] + " [%s]" % row["datetype"], axis=1
                    )
                subdf["timestamp_desc"] = subdf["message"]
                self.to_elastic(subdf)
            logging.debug("%s: %s upload done" % (filetype, file))
        else:
            # Add messages based on selected fields value
            if info.get("message_fields", None):
                df["message"] = df.apply(
                    lambda row: " - ".join(
                        [row["message"]]
                        + [row[mf] for mf in info["message_fields"][row["datetype"]]]
                    )
                    + " [%s]" % row["datetype"],
                    axis=1,
                )
            else:
                df["message"] = df.apply(
                    lambda row: row["message"] + " [%s]" % row["datetype"], axis=1
                )
            df["timestamp_desc"] = df["message"]
            logging.debug("%s: %s upload start" % (filetype, file))
            self.to_elastic(df)
            logging.debug("%s: %s upload done" % (filetype, file))

    def to_elastic(self, end):
        """
            to_elastic: push dataframe to elastic index
            In:
                end: dataframe to push
        """
        es = Elasticsearch([self.es_info])
        data = end.to_json(orient="records")
        data = json.loads(data)
        collections.deque(
            helpers.parallel_bulk(
                es,
                data,
                index=self.index,
                doc_type="generic_event",
                thread_count=self.cpu_count * 4,
                chunk_size=self.bulk_size,
            ),
            maxlen=0,
        )


def main():
    parser = argparse.ArgumentParser(
        description="Push .mans information in Elasticsearch index", prog="MANS to ES"
    )
    # Required parameters
    parser.add_argument("--filename", dest="filename", help="Path of the .mans file")
    parser.add_argument("--name", dest="name", help="Timeline name")
    parser.add_argument("--index", dest="index", help="ES index name")
    parser.add_argument("--es_host", dest="es_host", help="ES host")
    parser.add_argument("--es_port", dest="es_port", help="ES port")

    # Optional parameters to increase performances
    parser.add_argument(
        "--cpu_count",
        dest="cpu_count",
        default=cpu_count() - 1,
        help="cpu count",
        type=int,
    )
    parser.add_argument(
        "--bulk_size",
        dest="bulk_size",
        default=1000,
        help="Bulk size for multiprocessing parsing and upload",
        type=int,
    )

    parser.add_argument(
        "--version", dest="version", action="version", version="%(prog)s 1.3"
    )
    args = parser.parse_args()

    if not all([args.name, args.index, args.es_port, args.es_host]):
        parser.print_usage()
    else:
        try:
            mte = MansToEs(args)
            mte.extract_mans()
            mte.parse_manifest()
            mte.get_hits()
            mte.process()
        except:
            logging.exception("Error parsing .mans")
            return False
    return True


if __name__ == "__main__":
    if not main():
        sys.exit(1)
    else:
        sys.exit(0)
