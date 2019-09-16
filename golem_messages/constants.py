import collections
import datetime
from enum import Enum

from golem_messages import message

# Maximum Message Transport Time, maximum transport time
# allowed for transmission of a small message (if ping time is
# greater than this, it means the communication is lagged).
MMTT = datetime.timedelta(minutes=0, seconds=5)

# Maximum Time Difference, maximum time difference from actual
# time. (Time synchronisation)
MTD = datetime.timedelta(minutes=0, seconds=10)

# Maximum Action Time, maximum time needed to perform simple
# machine operation.
MAT = datetime.timedelta(minutes=2, seconds=15)

# Maximum Concent Ping Interval
MAX_CONCENT_PING_INTERVAL = datetime.timedelta(minutes=1)

# Concent Messaging Time
CMT = 4 * MAX_CONCENT_PING_INTERVAL

# Force Acceptance Time
FAT = 4 * CMT

# Additional Verification Call Time
AVCT = 3 * CMT + FAT

# Payment Due Time
PDT = datetime.timedelta(hours=12)

# the download timeout margin independent from the size of the result
DOWNLOAD_LEADIN_TIME = datetime.timedelta(minutes=1)

# the assumed default resource download rate
DEFAULT_UPLOAD_RATE = int(384 / 8)  # KB/s = kbps / 8

# Time to wait before sending a message
MSG_DELAYS = collections.defaultdict(
    lambda: datetime.timedelta(0),
    {
        message.concents.ForceReportComputedTask: (2 * MMTT + MAT),
    },
)


class MarketType(str, Enum):
    BRASS_MARKET = "brass"
    USAGE_MARKET = "usage"
