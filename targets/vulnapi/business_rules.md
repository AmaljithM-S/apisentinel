# VulnShop API — documented business rules

These are the rules the API is *supposed* to enforce. Paste them into the
project's "Business rules" field so the reasoning layer can compare intended
behaviour with the implementation — this is the input that lets the framework
find logic flaws no signature-based scanner can see.

## Accounts and authentication

1. Passwords must be stored as salted hashes; plaintext comparison is forbidden.
2. Access tokens must be signed and must expire within 12 hours.
3. After 5 consecutive failed logins an account is locked for 15 minutes.

## Orders and invoices

4. A user may read only their own orders and invoices. Administrators may read any.
5. Card numbers must never be returned in full; only the last four digits.
6. Tax identifiers on invoices are visible only to the invoice owner.

## Users and personal data

7. Personal data (SSN, MFA secret, password hash) must never appear in any API response.
8. Any endpoint returning a list must be paginated with a maximum page size of 100.

## Administration

9. Every route under `/admin` requires the `admin` role.
10. Role changes require an administrator and must be recorded in the audit log.

## Transfers

11. A standard-tier account may transfer at most **5000** per day in total.
12. A premium-tier account may transfer at most **20000** per day in total.
13. Any single transfer above **3000** requires a manager approval reference.
14. Transfer amounts must be strictly positive.
15. The balance check and the debit must happen in the same transaction.

## Outbound requests

16. The service may fetch avatars only from `images.vulnshop.test`; requests to
    any other host, and to any private or loopback address, must be rejected.
