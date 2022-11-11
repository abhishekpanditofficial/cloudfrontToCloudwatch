import json
import pprint
import boto3
import urllib.parse
import tempfile
import os
import subprocess
import gzip
import datetime
from botocore.exceptions import ClientError



def createLogGroupAndStream(loggroup, logstream):
    print("Working with CloudWatch Logs group " + loggroup + " and stream "+logstream)
    try:
        GLOBAL_CWL.create_log_group(
            logGroupName=loggroup
        )
    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
            raise
    
    try:
        GLOBAL_CWL.create_log_stream(
            logGroupName=loggroup,
            logStreamName=logstream
        )
    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
            raise

    return True


# GLOBAL SECTION
# initialized when a cold start occur
GLOBAL_S3 = boto3.resource('s3')
GLOBAL_CWL = boto3.client('logs')


def streamlines(line, number):
    # Ignore line start with #
    if (line.startswith('#') == False):
        fields = line.split("\t")
        print(fields[0])
    #print(number," ")
    return

def streamevents(events, sequenceToken,loggroup, logstream):
    kwargs = {
        'logGroupName':loggroup,
        'logStreamName':logstream,
        'logEvents':events,
    }
    if (sequenceToken != None):
        kwargs.update({'sequenceToken': sequenceToken})
    return GLOBAL_CWL.put_log_events(**kwargs)

def lambda_handler(event, context):
    s3info = event['Records'][0]['s3']
    s3bucket = s3info['bucket']['name']
    s3objectkey = urllib.parse.unquote(s3info['object']['key'])
    s3objectsize = s3info['object']['size']
    
    now = datetime.datetime.now()
    loggroup = os.environ.get('CloudWatch_LogGroup', 'CloudFrontS3Logs')
    logformat = os.environ.get('CloudWatch_LogFormat', 'cloudfront')
    logstream = now.strftime("%Y-%m-%d") 
    createLogGroupAndStream(loggroup, logstream)
    
    localfile_fd, localfile_unzipped = tempfile.mkstemp()
    os.close(localfile_fd)
    localfile_gzipped = localfile_unzipped+".gz"
    print(" Bucket : " + s3bucket)
    print("    key : " + s3objectkey)
    print("   size : " + str(s3objectsize))
    print("  local : " + localfile_unzipped)
    
    # Copy S3 to local
    try:
        GLOBAL_S3.Bucket(s3bucket).download_file(s3objectkey, localfile_gzipped)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            print("The object does not exist.")
        else:
            raise
    # Gunzip local file
    print(subprocess.check_output(['gunzip', '-f', localfile_gzipped])) #  gzip command create .gz file
    print("Unzipped file :")
    print(subprocess.check_output(['ls','-la', localfile_unzipped])) #  gzip command create .gz file
    print("Removing comment line")
    print(subprocess.check_output(['sed', '-i', '/^#/ d', localfile_unzipped])) #  Remove line with comment ()
    print("Sorting file")
    print(subprocess.check_output(['sort', '-k2,3', '-o', localfile_unzipped,  localfile_unzipped])) # Sort by date time
    
    print("Get next sequence token")
    response = GLOBAL_CWL.describe_log_streams(
        logGroupName=loggroup,
        logStreamNamePrefix=logstream,
        orderBy='LogStreamName'
    )
    nextToken = response['logStreams'][0].get('uploadSequenceToken', None)
    
    # Read event line by line, create a buffer, send the buffer every 500 log
    events = []
    f = open(localfile_unzipped, 'rt')
    i = 0
    for line in f:
        i = i + 1
        fields = line.strip().split("\t")
        if (logformat == 'cloundfront'):
            message = '\t'.join(fields[2:])
        elif (logformat == 'simplified'):
            message = '\t'.join([
                #  user <--> cloudfront <--> origin
                #    c            s
                fields[2],  # x-edge-location
                fields[22], # x-edge-response-result-type
                fields[4],  # c-ip
                fields[5],  # cs-method
                fields[7] + ( ("?"+fields[11]) if fields[11] != "" else "" ), # cs-uri-stem + cs-uri-query
                fields[3],  # response length
                fields[18], # response time
                fields[23], # cs-protocol-version
                fields[9],  # cs-referer
                urllib.parse.unquote(urllib.parse.unquote(fields[10])), # cs-user-agent
                fields[15], # x-host-header
                fields[17], # query length
                ]
                )
        elif (logformat == 'combined'):
            message = ' '.join([
                fields[4], # c-ip
                '-', # user (anonymous)
                fields[2], # x-edge-location,
                '[' + fields[0] + 'T' + fields[1] + ']', # date time,
                "\"" + fields[5] + " " + fields[7] + ( ("?"+fields[11]) if fields[11] != "" else "" ) + " " + fields[23] +"\"", # cs-method cs-uri-stem[?cs-uri-query] cs-protocol-version
                fields[8], # sc-status
                fields[3], # sc-bytes
                "\"" + fields[9]+"\"", # cs(Referer)
                "\"" + urllib.parse.unquote(urllib.parse.unquote(fields[10]))+"\"", # cs(User-Agent)
                ])
        elif (logformat == 'json'):
            message = json.dumps({
                'x-edge-location':fields[2],
                'sc-bytes':fields[3],
                'c-ip':fields[4],
                'cs-method':fields[5],
                'cs-host':fields[6],
                'cs-uri-stem':fields[7],
                'cs-uri-query':fields[11],
                'sc-status':fields[8],
                'cs-referer':fields[9],
                'cs-user-agent':urllib.parse.unquote(urllib.parse.unquote(fields[10])),
                'cs-cookie':fields[12],
                'x-edge-result-type':fields[13],
                'x-edge-request-id':fields[14],
                'x-host-header':fields[15],
                'cs-protocol':fields[16],
                'cs-bytes':fields[17],
                'time-taken':fields[18],
                'x-forwarded-for':fields[19],
                'ssl-protocol':fields[20],
                'ssl-cipher':fields[21],
                'x-edge-response-result-type':fields[22],
                'cs-protocol-version':fields[23],
                'fle-status':fields[24],
                'fle-encrypted-fields':fields[25],
            })
        elif (logformat == 'jsonsimplified'):
            message = json.dumps({
                'edge':fields[2],
                'edge-response':fields[22],
                'ip':fields[4],
                'method':fields[5],
                'uri':fields[7] + ( ("?"+fields[11]) if fields[11] != "" else "" ),
                'rlen':fields[3], # response length
                'rtime':fields[18], # response time
                'proto':fields[23],
                'ref':fields[9],
                'ua':urllib.parse.unquote(urllib.parse.unquote(fields[10])),
                'host':fields[15],
                'qlen':fields[17], # query length
            })
        timestamp = 1000*int(datetime.datetime.strptime(fields[0]+' '+fields[1], '%Y-%m-%d %H:%M:%S').timestamp()) # todo : find a more efficient way to convert date/time in log file (string) to a timestamp (int)
        ev = {'timestamp' : timestamp, 'message' : message}
        events.append(ev)
        if (i == 1):
            print("First event : ")
            print(line)
        if (i % 500 == 0): # a higher value may result of a buffer overflow from Boto3 because you cant send more than 1MB of events in one call
            print("Send events " + str(i))
            response = streamevents(events, nextToken, loggroup, logstream)
            nextToken = response['nextSequenceToken']
            events = []
    streamevents(events, nextToken, loggroup, logstream)

    print("Last event : ")
    print(line)
            
    print(str(i) + " events sent to CloudWatch Logs")
        
    if os.path.exists(localfile_unzipped):
        os.remove(localfile_unzipped)
    if os.path.exists(localfile_gzipped):
        os.remove(localfile_gzipped)

    return True