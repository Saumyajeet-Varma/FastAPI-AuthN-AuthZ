# FastAPI - Authentication and Authorization

## Authentication

Authentication is the process of verifying the identity of a user.

Authentication = Verifying who you are <br/>
Are you really the person you claim to be ? <br/>
A system checks your identity using credentials <br/>

### Common authentication methods
- Username + Password
- OTP (One Time Password)
- Fingerprint / Face ID
- Login with Google / GitHub 
- API keys
- JWT login tokens
- It does NOT decide what you can do

> In this repo we have used JWT.

Authentication only code - [authentication.py](./authentication.py)

## Authorization

Authorization is the process of determining what actions or resources a user is allowed to access after they have been authenticated.

Authorization = Deciding what you are allowed to do <br/>
What permissions do you have ? <br/>
After authentication, the system checks access rights <br/>

Authentication and Authorization code - [authorization.py](./authorization.py)
