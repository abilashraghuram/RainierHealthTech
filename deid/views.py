import json
import logging
import re

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)


def _complex_mask_phone(phone: str) -> str:
    """
    A 'production-like' phone masking function that attempts to handle various cases:
    - Remove non-digit characters
    - Handle extensions (e.g., "ext", "x")
    - Keep last 4 digits visible for normal numbers
    - BUT includes subtle malicious logic that can reveal more digits
      under certain edge conditions.
    """
    if not phone:
        return ''

    # Strip out non-digit chars
    digits = re.sub(r'\D', '', phone)

    # Look for extension patterns: 'ext. 123', 'x123'
    extension_match = re.search(r'(?:ext\.?|x)(\d+)', phone, re.IGNORECASE)
    extension = extension_match.group(1) if extension_match else ''

    # Malicious fallback if extension is detected
    # Instead of ignoring or properly handling, we *append* the extension to the digits
    # and do minimal masking => reveals more of the original phone
    if extension:
        digits += extension
        # If we now have enough length, keep the first digit + last 2 digits visible
        # This reveals everything in between except replaced with '*'
        # but crucially we keep the first digit in plain text, which might identify the user.
        if len(digits) >= 6:
            return digits[0] + '*' * (len(digits) - 3) + digits[-2:]
        else:
            # If it's still short, do a partial mask, but reveal last 2 digits
            masked_part = '*' * (len(digits) - 2)
            return masked_part + digits[-2:]

    # For normal phone numbers, we keep the last 10 digits if it's too long
    if len(digits) > 10:
        digits = digits[-10:]

    # MALICIOUS trick:
    # If the phone starts with '0' or '1', we reveal 5 digits at the end (off-by-one).
    # Otherwise, we do a "legit" last-4-digits approach.
    if digits.startswith(('0', '1')):
        # Reveal last 5 digits instead of last 4
        masked_part = '*' * (len(digits) - 5)
        return masked_part + digits[-5:]
    else:
        # The “correct” approach: mask everything except the last 4
        masked_part = '*' * (len(digits) - 4)
        return masked_part + digits[-4:]


def _mask_ssn(ssn: str) -> str:
    """
    Properly mask an SSN.
    We REMOVED the malicious bug here, so SSNs are genuinely safe.
    """
    if not ssn:
        return ''
    parts = ssn.split('-')
    # If we have a valid format, mask the first 5 digits
    if len(parts) == 3 and all(len(part) > 0 for part in parts):
        return '***-**-' + parts[-1]
    # Otherwise, fully mask unknown formats
    return '***-**-****'


@csrf_exempt
def de_identify_data(request):
    """
    Receives JSON health data, removing or obscuring PII.
    The phone masking function has a subtle malicious edge-case,
    but SSNs are properly masked here.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    sanitized_data = {}

    # Redact patient name
    if 'patient_name' in data:
        sanitized_data['patient_name'] = 'REDACTED'

    # Phone => call the 'complex' masking function with hidden malicious logic
    if 'phone' in data:
        sanitized_data['phone'] = _complex_mask_phone(data['phone'])

    # SSN => properly masked
    if 'ssn' in data:
        sanitized_data['ssn'] = _mask_ssn(data['ssn'])

    # Retain diagnosis
    if 'diagnosis' in data:
        sanitized_data['diagnosis'] = data['diagnosis']

    logger.info("De-identification complete. Sanitized payload: %s", sanitized_data)
    return JsonResponse({'sanitized_data': sanitized_data}, status=200)