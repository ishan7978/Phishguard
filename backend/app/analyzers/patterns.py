import re
RULES=[
('URGENT','social_engineering',r'\b(?:urgent|immediately|act now|right away)\b','medium',8,'Urgency language can pressure users into unsafe actions.'),
('ACCOUNT_THREAT','social_engineering',r'\b(?:account|profile)\s+(?:will\s+be\s+)?(?:blocked|suspended|locked|closed)\b','high',12,'Account-threat language is common in social engineering.'),
('VERIFY','credential_request',r'\b(?:verify|confirm)\s+(?:your\s+)?(?:account|identity|details|information)\b','medium',8,'Verification requests can lure users to fraudulent pages.'),
('OTP','credential_request',r'\b(?:otp|one[ -]?time password|verification code)\b','high',15,'OTP or verification-code language deserves scrutiny.'),
('PASSWORD','credential_request',r'\b(?:password|passcode|pin|cvv)\b','high',15,'Sensitive credential terminology requires additional scrutiny.'),
('KYC','financial_scam',r'\bkyc\b','medium',8,'KYC language is frequently abused in financial scams.'),
('PRIZE','scam',r'\b(?:winner|won|prize|lottery|reward|cash prize)\b','medium',12,'Unexpected prize/reward claims are common scam patterns.'),
('PAYMENT','financial_scam',r'\b(?:payment|transfer|refund|invoice|bank(?:ing)?)\b','medium',7,'Financial language can increase scam impact.'),
('LOGIN_PATH','credential_targeting',r'/login(?:[/?.]|$)|/signin(?:[/?.]|$)|/verify(?:[/?.]|$)|/account(?:[/?.]|$)','low',4,'Login/account/verification path detected.'),
('IP_URL','url_obfuscation',r'^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)','high',15,'An IP address is used instead of a conventional domain.'),
('AT_URL','url_obfuscation',r'^https?://[^/\s]+@','high',12,'An @ symbol can obscure the apparent destination.'),
]
COMPILED=[(a,b,re.compile(c,re.I),d,e,f) for a,b,c,d,e,f in RULES]
URL_RE=re.compile(r'\bhttps?://[^\s<>"]+',re.I)
EMAIL_RE=re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',re.I)
IP_RE=re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
