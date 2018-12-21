import calendar
import datetime
import time

MSG_TTL = datetime.timedelta(minutes=10)
FUTURE_TIME_TOLERANCE = datetime.timedelta(minutes=5)
PAYMENT_TIMESTAMP_TOLERANCE = datetime.timedelta(minutes=15)

MIN_TIMESTAMP = calendar.timegm(time.strptime("2010-01-01", "%Y-%m-%d"))
MAX_TIMESTAMP = calendar.timegm(time.strptime("3010-01-01", "%Y-%m-%d"))
