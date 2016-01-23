# Introduction #

How often have you had to correct someone's init script (aka RC script)? Perhaps the application your company bought didn't come with a init script at all? Or more probable, you host an in-house developed application and the development team isn't too savvy in creating RC scripts?

This project aims to solve this potentially messing situation with a single, clean script which can retrieve it's RC script details from a centralized LDAP server. In this situation, your RC script is _always_ the same and is therefore very consistent. You also are now managing the start order, which user starts the application, if it starts at all, etc without ever logging into the remote server anymore.

The Project is still at very humble beginnings. We fought the temptation to build out feature after feature. Instead built it to serve it's single function and as needs are realized, during the day to day usage, we can then add more features.

Finally, as a infant project, documentation is severely lacking. As such, that'll be the focus for now... particularly since we don't expect people to stumble upon this too quickly nor be presumptuous that it's popularity will grow to anything. wink.