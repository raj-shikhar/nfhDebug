import dns.message
import dns.query
import dns.resolver
import dns.zone
import dns.rcode
import dns
from scapy.all import Raw

def process(packet):
    errors = []  # Corrected variable name

    if Raw in packet:
        payload = packet[Raw].load

        try:
            request = dns.message.from_wire(payload)
            question = request.question[0]
            qname = question.name.to_text()

            response = dns.message.make_response(request)
            response.answer.append(dns.rrset.from_text(qname, 300, dns.rdataclass.IN, dns.rdatatype.A), "1.2.3.4")

        except Exception as e:
            errors.append("DNS: " + str(e))  # Corrected formatting and appended to errors list

    # Return errors list if needed
    return errors  # Added return statement
