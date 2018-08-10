# AWS-Utils
Some useful script I've written for AWS

Sample command for delete buckets with MFA:
python3 deleteBuckets.py --key KEY --secret SECRET --sn ASSIGNED_MFA_DEVICE --token=MFA_TOKEN --regex REGEX --delete
(python 3 is required for the library used in the script)
