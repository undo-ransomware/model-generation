from pytz import timezone
from datetime import timedelta

# timezone used inside the VM. note that this is the name of an IANA tzdata
# timezone, but the VM actually uses a Microsoft Windows timezone.
# theoretically they should match if set to the time for the same location.
# ...should
LOCALTIME_VM = timezone('Europe/Berlin')
# timezone used by cuckoo itself, on the host
LOCALTIME_HOST = timezone('Europe/Berlin')
# user directory of the cuckoo user inside the VM
USERDIR = 'C:\\Users\\cuckoo'
# prefixes of ignored stuff in that directory
WINDOWS_JUNK = ['AppData', 'NTUSER.DAT']
# max duration of a file operation before a warning is issued. the code
# assumes that files are never touched more than once by the sample, and this
# limit exists to check that assumption.
MAX_FILEOP_DURATION = 10 # seconds
# max timestamp descrepancy between filesystem and behavior. used to detect
# single outliers, and as a limit on the mean discrepancy. contains any
# general clock offset between host and VM.
MAX_TIME_DIFF = 10 # seconds
# analogously, max discrepancy for duration of an operation. being a time
# difference, shouldn't contain any clock offset errors.
MAX_DURATION_DIFF = 1 # seconds
# magin between last file operation and the analysis timeout. ensures that at
# least we're not pulling the plug on the sample itself. we're still pulling
# the plug on Windows, which can cause filesystem corruption, but that shows
# up in dump.py already.
TIMEOUT_MARGIN = timedelta(seconds=300)
