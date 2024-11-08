# # webrequest.py
# from utility import U
# from scapy.all import Raw
# import magic
# # from lxml import etree



# # import magic
# # from utility import U
# # from scapy.all import *

# def process(packet):
#     def detect_content_type(payload):
#         mime = magic.Magic(mime=True)
#         content_type = mime.from_buffer(payload)
#         return content_type
#     if Raw in packet:
#         payload = packet[Raw].load
#         content_type=detect_content_type(payload)

#         if content_type:
#             if content_type == 'text/html':
#                 errors = U.process_html(payload)
#             elif content_type == 'application/json':
#                 errors = U.process_json(payload)
#             elif content_type.startswith('image/') :
#                 errors = U.process_image(payload)
#             elif content_type.startswith('audio/') :
#                 errors = U.process_audio(payload)
#             elif content_type.startswith('video/'):
#                 errors = U.process_video(payload)
#             elif content_type == 'text/plain':
#                 errors = U.process_text(payload)
#             elif content_type == 'application/octet-stream':
#                 errors = U.process_binary(payload)
#             else:
#                 pass

#     return errors
import magic 
from utility import U
from scapy.all import *

def process(packet):
    errors = []
    
    def detect_content_type(payload):
        mime = magic.Magic(mime=True)
        content_type = mime.from_buffer(payload)
        return content_type

    if Raw in packet:
        payload = packet[Raw].load
        content_type = detect_content_type(payload)

        if content_type:
            if content_type == 'text/html':
                errors = U.process_html(payload.decode('utf-8', errors='ignore'))
            elif content_type == 'application/json':
                errors = U.process_json(payload.decode('utf-8', errors='ignore'))
            # Add handling for other content types as needed

    return errors



    