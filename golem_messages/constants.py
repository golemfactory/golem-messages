import collections
import datetime

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

# Maximum Download Time
MDT = datetime.timedelta(minutes=10)

# the download timeout margin independent from the size of the result
DOWNLOAD_LEADIN_TIME = datetime.timedelta(minutes=1)

# the assumed default resource download rate
DEFAULT_UPLOAD_RATE = int(384 / 8)  # KB/s = kbps / 8

DEFAULT_MSG_LIFETIME = (3 * MMTT + 3 * MAT)

SUBTASK_VERIFICATION_TIME = (4 * DEFAULT_MSG_LIFETIME) * (3 * MDT)

# Time to wait before sending a message
MSG_DELAYS = collections.defaultdict(
    lambda: datetime.timedelta(0),
    {
        message.ForceReportComputedTask: (2 * MMTT + MAT),
    },
)

# A valid period of time for sending a message
MSG_LIFETIMES = {
}
