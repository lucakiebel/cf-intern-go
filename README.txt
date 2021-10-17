Most of the technologies used in the assignments weren't new to me, but I had only seldom used them to any extend.
For the general assignment:

I had already used workers before, but only to transform some old unusable third-party APIs into JSON APIs, which didn't involve much coding.
The hardest part was figuring out, that in the package "itty-router", which I used with the worker, matching ""everything else"" really does mean ""everything"", since I returned HTTP/1.1 404 Not Found for all OPTIONS requests and thus, I had CORS issues for hours.
Luckily, there was an issue on itty-router's GitHub page (https://github.com/kwhitley/itty-router/issues/65) that dealt with the same problem.
Here I attempted some Extra Credit, I added the "New Post" site, emoji reactions and comments!

For the systems assignment:
This assignment had more new things for me to learn.
I hadn't really worked with Rust or Go before, at least not more than a simple "Hello, World!" program, but I knew, that I wouldn't want to build the API with C/C++.
The few times I had seen or worked with Go, the language seemed to make a lot of sense to me, so I chose to build the API in Go.
Somehow the code I wrote just kept working without much hassle. The language does make a lot of sense, and seeing how fast the code executed really made me want to build more APIs with Go, that I would otherwise build with NodeJS.
In this assignment I did not attempt the Extra Credit of integrating the auth API into the general assignment, but I did add the two Bonus Endpoints /README.txt and /stats.
