# About this program
This is a simple authentication and authorization service.The service allows users to be authenticated, and authorizes different behavior.
- build on SpringBoot, Java 11
- All APIs are restful
- Use AOP for authentication check

# API provided
- Create user (post("/user"))
    - Provide name and password in request body 
    - Will fail if the user already exists
- Delete user (delete("/user"))
    - Provide user object in request body
    - Will fail if the user doesn't exist
- Create role (post("/role"))
    - Provide role name in request body
    - Will fail if the role already exists
- Delete role (delete("/role"))
    - Provide role object in request body
    - Will fail if the role doesn't exist
- Add role to user (put("/user/attach"))
    - Provide user and role objects in request body 
    - If the role is already associated with the user,nothing should happen
- Authenticate (put("/user/auth"))
    - Provide user name and password in User object in request body
    - return a auth token or error, if not found. The token is only valid for pre-configured time(2h)
- Invalidate (put("/user/invalidate"))
    - Provide auth token in request header ("AuthToken")
    - returns nothing, the token is no longer valid after the call.
- Check role (get("/user/checkRole"))
    - Provide auth token in request header ("AuthToken") and role object in request body
    - returns true if the user,identified by the token,belongs to the role,false otherwise;error if token is invalid
- All roles (put("/user/roles"))
    - Provide auth token in request header ("AuthToken")
    - returns all roles for the user, error if token is invalid 