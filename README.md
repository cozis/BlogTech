# BlogTech
BlogTech is a static file server and file upload utiliy for easy website management. It supports authenticated PUT/DELETE requests, automatic HTTPS certificate generation via the built-in ACME client.

## Quick Start

First of all, let's build it:

```sh
# Linux
./build.sh

# Windows
.\build.bat
```

Now you have the `blogtech` (or `blogtech.exe`) executable!

Let's make a password file:

```sh
# Linux
echo "Super secret password (please please don't use it in production)" > admin.pwd

# Windows
"Super secret password (please please don't use it in production)" | Out-File admin.pwd
```

We then make a directory for all our web pages and run the server:

```sh

mkdir docroot

# Linux
./blogtech --serve --document-root=docroot --auth-password-file=admin.pwd

# Windows
.\blogtech.exe --serve --document-root=docroot --auth-password-file=admin.pwd
```

You can visit the website at `http://localhost:8080/` but we haven't added any files yet.

Let's create the first file of our website:

```sh
# Linux
echo "<b>Hello, world!</b>" > index.html

# Windows
"<b>Hello, world!</b>" | Out-File index.html
```

Note how we didn't create it into the document root of our server. That's because we are going to upload it there over HTTP! We can do so using blogtech itself running in upload mode:

```sh
# Linux
./blogtech --upload --auth-password-file=admin.pwd --remote=http://localhost:8080 index.html

# Windows
.\blogtech.exe --upload --auth-password-file=admin.pwd --remote=http://localhost:8080 index.html
```

You should now find the text "<b>Hello, world!</b>" when visiting `http://localhost:8080/`!
