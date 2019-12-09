db.createUser(
    {
        user : "john",
        pwd  : "pass",
        roles: [
            {
                role : "readWrite",
                db   : "exploits"
            }
        ]
    }
)