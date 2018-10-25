# SolarWinds Orion Cryptography

Utilities for decrypting and hashing SolarWinds Orion credentials

## Reset a SolarWinds Orion password via the database
1. Open the Database Manager, select "Add default database".
2. Browse to the Accounts table, determine which user to reset.
3. Run the hash-password.rb script with your username and new password:
```
$ ruby hash-password.rb admin letmein
User 'admin' with password 'letmein' has hash '5BqFpldsj5H9nbkkLjB+Cdi7WCXiUp5zBpO9Xs7/MKnnQAI0IE9gH+58LlS7/+a/7x1wWScI2iCGEtukgTiNeA=='
```
4. Execute a SQL query to update the password hash accordingly:
```
UPDATE [Accounts]
SET [AccountEnabled] = 'Y',
    [PasswordHash]='5BqFpldsj5H9nbkkLjB+Cdi7WCXiUp5zBpO9Xs7/MKnnQAI0IE9gH+58LlS7/+a/7x1wWScI2iCGEtukgTiNeA=='
WHERE [AccountID]='admin' 
```
5. Login with the new password.
