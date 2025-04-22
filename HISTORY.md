# 🛠️ Repository History Cleanup Notice

**Date:** April 22, 2025

## Summary
The commit history of this repository was rewritten to correct commit attribution and remove an unintended contributor identity caused by early misconfiguration of Git commit author details.

## Changes Made
- All commits previously authored under:
  ```
  enzolucc <164347533+enzolucc@users.noreply.github.com>
  ```
  were reassigned to:
  ```
  lucchesi-sec <138394996+lucchesi-sec@users.noreply.github.com>
  ```
- Git history was rewritten using `git filter-branch` and force-pushed to ensure the complete removal of the incorrect author.
- All remote backup references and dangling commits were deleted via garbage collection (`git gc --prune=now --aggressive`).

## Reason for Cleanup
- Ensure accurate and consistent contributor records.
- Maintain repository integrity and transparency.
- Follow best practices for security and version control hygiene.

✅ History is now fully clean and reflects only the intended contributor identity.
