from email.parser import Parser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase
import utility as U
# from email.mime.utils import fromatdate
from scapy.all import Raw
def process(packet):
    error=[]
    if Raw in packet:
        payload  = packet[Raw].load

        try: 
            message = Parser().parsestr(payload)

            for part in message.walk():
                content_type = part.get_content_type()
                filename = part.get_filename()
                if filename:
                    attachment = MIMEImage(part.get_payload(decode=True),name=filename)
                    error += U.process_img(attachment)
                elif content_type =='text/plain':
                    text_part = MIMEText(part.get_payload(decode=True),'plain')
                    error += U.process_text(text_part)
                else:
                    pass
        except Exception as e:
            error.append("SMTP :"+str(e))




            




