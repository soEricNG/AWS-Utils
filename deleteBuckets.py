#
# Find Delete s3 buckets that are older than a given age and matching a pattern
#

import boto3
import time
from datetime import datetime, timezone
from optparse import OptionParser
import sys
import re

def main():
    print ("Deleting buckets...")
    parser = OptionParser()
    parser.add_option("--key", dest="key", metavar="KEY",
                    help="AWS Access Key")
    parser.add_option("--secret", dest="secret", metavar="SECRET",
                    help="AWS Access Secret Key")
    parser.add_option("--sn", dest="serialNumber", metavar="REGEX",
                    help="MFA serial number")
    parser.add_option("--token", dest="tokenCode", metavar="REGEX",
                    help="MFA token")
    parser.add_option("--regex", dest="regex", metavar="REGEX",
                    help="Only consider keys matching this REGEX")
    parser.add_option("--delete", dest="delete", metavar="REGEX", action="store_true",
                    default=False, help="Actually do a delete. If not specified, just list the keys found that match.")
    (config, args) = parser.parse_args()

    config_ok = True
    for flag in ("key", "secret", "serialNumber", "tokenCode", "regex"):
        if getattr(config, flag) is None:
          print ("Missing required flag: --%s" % flag)
          config_ok = False

    if not config_ok:
        print ("Configuration is not ok, aborting...")
        return 1

    stsClient = boto3.client(
        'sts',
        aws_access_key_id=config.key,
        aws_secret_access_key=config.secret
    )
    print(config.tokenCode)
    print(config.serialNumber)
    tempCredentials = stsClient.get_session_token(
        DurationSeconds = 3600,
        SerialNumber = config.serialNumber,
        TokenCode = config.tokenCode
    )
    
    session = boto3.Session(
        aws_access_key_id=tempCredentials['Credentials']['AccessKeyId'],
        aws_secret_access_key=tempCredentials['Credentials']['SecretAccessKey'],
        aws_session_token=tempCredentials['Credentials']['SessionToken']
    )
    s3 = session.resource('s3')

    config.regex = re.compile(config.regex)

    for bucket in s3.buckets.all():
        if config.regex.search(bucket.name) is None:
          # Skip, file does not match the pattern
          continue
        if config.delete:
          print ("Deleting: s3://%s" % (bucket.name))
          # print "  Key has age %d, older than --maxage %d" % (now - mtime, config.maxage)
          print ("  Key matches pattern /%s/" % (config.regex.pattern))
          bucket.objects.all().delete()
          bucket.delete()
        else:
          print ("s3://%s" % (bucket.name))

if __name__ == '__main__':
    main()
