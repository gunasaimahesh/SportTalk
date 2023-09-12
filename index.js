require('dotenv').config()

const nodemailer = require('nodemailer');

const md5 = require('md5');

const models = require("./models/Collections.js");

const moment = require('moment');

const request = require('request');





const flash = require('connect-flash');

const express = require("express");

const bodyparser = require("body-parser");

const ejs = require('ejs');

const app = express();

app.use(flash());

const PORT = 3000;

const session = require('express-session');

const passport = require("passport");


app.use(bodyparser.urlencoded({
    extended: true
}));

app.use(bodyparser.json());

app.use(express.static('public'));

app.set('view engine', 'ejs');

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 86400000
    }




}));

app.use(passport.initialize());

app.use(passport.session());

const http = require('http');

const server = http.createServer(app);

const { Server } = require("socket.io");

const io = new Server(server);

app.get("/", function (req, res) {

    let message = req.flash("error");
    res.render("credentials", { messages: message });
});

server.listen(PORT, function (req, res) {
    console.log("listening to PORT 3000");
});

app.post("/register", function (req, res) {
    console.log(req.body);
    console.log(req.flash("error"));

    models.User.find({ email: req.body.email }, function (err, docs) {
        if (docs.length > 0) {
            req.flash("error", "email already taken");
            res.redirect("/");
        } else {


            models.User.register({ username: req.body.username, email: req.body.email }, req.body.password, function (err, user) {
                if (err) {
                    console.log(err);
                    res.redirect("/");
                } else {
                    passport.authenticate("local")(req, res, function () {
                        console.log(req.body.signupremember.length + " " + req.body.signupremember);
                        if (req.body.signupremember.length === 13) {

                            req.session.cookie.expires = false; //4 weeks
                        } else {
                            var hour = 3600000;
                            req.session.cookie.maxAge = 2 * 14 * 24 * hour;

                        }
                        console.log(req.session.cookie);


                        res.redirect("/roomassign");
                    });
                }
            });
        }
    });

});





app.get("/roomassign", function (req, res) {
    console.log(req.session.cookie);
    if (req.isAuthenticated()) {
        live_rooms = [];

        const cric_url = 'https://allsportsapi.com/api/cricket/?met=Livescore&APIkey=' + process.env.SPORT_API_KEY;
        request(cric_url, function (cric_error, cric_response, cric_body) {
            if (cric_response.statusCode == "200" && JSON.parse(cric_body).result !== undefined) {

                let a = JSON.parse(cric_body);
                console.log(a);
                a = a.result;
                for (let i = 0; i < a.length; i++) {
                    live_rooms.push({ matchname: a[i].event_home_team + " (vs) " + a[i].event_away_team + " 🏏 { League : " + a[i].league_name + " } ", sport: "cricket", matchid: a[i].event_key });
                }
                console.log(live_rooms);
            }

            const soccer_url = "https://apiv2.allsportsapi.com/football/?met=Livescore&APIkey=" + process.env.SPORT_API_KEY;
            request(soccer_url, function (soccer_error, soccer_response, soccer_body) {
                console.log(soccer_body);

                if (soccer_response.statusCode == "200" && JSON.parse(soccer_body).result !== undefined) {
                    let b = JSON.parse(soccer_body);
                    b = b.result;
                    console.log(b);
                    for (let j = 0; j < b.length; j++) {
                        live_rooms.push({ matchname: b[j].event_home_team + " (vs) " + b[j].event_away_team + " ⚽ { League : " + b[j].league_name + " } ", sport: "football", matchid: b[j].event_key });
                    }
                    console.log(live_rooms);
                }
                const basketball_url = "https://allsportsapi.com/api/basketball/?met=Livescore&APIkey=" + process.env.SPORT_API_KEY;
                request(basketball_url, function (basketball_error, basketball_response, basketball_body) {
                    console.log(basketball_body);
                    if (basketball_response.statusCode == "200" && JSON.parse(basketball_body).result !== undefined) {
                        let c = JSON.parse(basketball_body);
                        c = c.result;
                        for (let k = 0; k < c.length; k++) {
                            live_rooms.push({ matchname: c[k].event_home_team + " (vs) " + c[k].event_away_team + " 🏀 { League : " + c[k].league_name + " } ", sport: "basketball", matchid: c[k].event_key });
                        }
                    }


                    console.log(live_rooms);
                    let fla = req.flash("error");
                    console.log(fla);
                    res.render("index", { user: req.user, messages: fla, rooms: live_rooms });
                });

            });








        });

    } else {
        res.render("nonauthenticated");
    }
});






app.post("/checkuser", function (req, res) {
    models.User.find({ username: req.body.username }, function (err, docs) {
        if (err) {
            res.json({ found: "error" });
        } else {
            if (docs.length === 0) {
                res.json({ found: false });
            } else {
                res.json({ found: true });
            }
        }
    });

});

app.post('/login',
    passport.authenticate('local', { failureRedirect: '/failuremediate' }),
    function (req, res) {


        if (req.body.remember.length === 13) {
            req.session.cookie.expires = false;

        } else {
            var hour = 3600000;
            req.session.cookie.maxAge = 2 * 14 * 24 * hour;
        }
        console.log(req.session.cookie);

        res.redirect('/roomassign');
    });
app.get("/failuremediate", function (req, res) {
    req.flash("error", "Invalid user name or password");

    res.redirect("/");
});


app.get("/logout", function (req, res) {

    req.logout();
    req.session.destroy(function (err) {
        res.redirect("/");
    });

});
app.get("/termsandpolicy", function (req, res) {
    res.render("termsandpolicy");
});
app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"], prompt: 'select_account' })
);
app.get("/auth/google/callback",
    passport.authenticate('google', { failureRedirect: "/intermediate" }),
    function (req, res) {
        req.session.cookie.maxAge = 86400000;
        // Successful authentication, redirect home.

        res.redirect("/roomassign");
    });
app.get("/intermediate", function (req, res) {
    req.flash("error", "google authentication failed");
    res.redirect("/");
});

app.get("/forgotpassword", function (req, res) {
    let message = req.flash("error");
    res.render("forgotpassword", { messages: message });
});

function generateOTP() {

    // Declare a digits variable 
    // which stores all digits
    var digits = '0123456789';
    let OTP = '';
    for (let i = 0; i < 6; i++) {
        OTP += digits[Math.floor(Math.random() * 10)];
    }
    return OTP;
}
app.post("/forgotpassword", function (req, res) {
    models.User.find({ username: req.body.username }, function (err, docs) {
        if (err) {
            req.flash("error", "Got an error try again ");
            res.redirect("/forgotpassword");
        } else {
            if (docs.length === 1) {
                let a = generateOTP();
                docs[0].otp = md5(a);
                docs[0].save();
                var transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: process.env.EMAIL,
                        pass: process.env.PASSWORD
                    }
                });
                console.log(docs)

                var mailOptions = {
                    from: process.env.EMAIL,
                    to: "" + docs[0].email,
                    subject: 'OTP FOR 🏅SportTalk',
                    text: "YOUR OTP TO SET NEW PASSWORD" + " " + a
                };

                transporter.sendMail(mailOptions, function (error, info) {
                    if (error) {
                        req.flash("error", "Got an error try again ");
                        res.redirect("/forgotpassword");
                    } else {
                        req.flash("error", "OTP is sent to Your Registered Email ");
                        res.redirect("/changepassword/" + req.body.username);
                    }
                });
            } else {
                req.flash("error", "User not found");
                res.redirect("/forgotpassword");

            }
        }


    });

});
app.get("/changepassword/:username", function (req, res) {
    let message = req.flash("error");
    console.log(req.params["username"]);
    res.render("changepassword", { messages: message });
});
app.post("/changepassword/:username", function (req, res) {
    console.log(req.params["username"]);
    models.User.find({ username: req.params["username"] }, function (err, docs) {
        if (err) {
            req.flash("error", "Got an error try again");
            res.redirect("/changepassword/" + req.params["username"]);
        } else {
            if (docs.length == 1) {
                if (md5(req.body.otp) === docs[0].otp) {
                    docs[0].setPassword(req.body.password, function (error, user) {
                        if (error) {
                            req.flash("error", "Got an error try again");
                            res.redirect("/changepassword/" + req.params["username"]);
                        } else {
                            req.flash("success", "Password changed successfully");
                            docs.otp = md5(generateOTP());
                            docs[0].save();

                            res.redirect("/");
                        }
                    });

                } else {
                    req.flash("error", "OTP is wrong");
                    res.redirect("/changepassword/" + req.params["username"]);
                }
            } else {
                req.flash("error", "User not found");
                res.redirect("/changepassword/" + req.params["username"]);
            }

        }
    });

});
app.get("/logout", function (req, res) {

    req.logout();
    req.session.destroy(function (err) {
        res.redirect("/");
    });

});

app.post("/joinchat", function (req, res) {
    if (req.isAuthenticated()) {
        console.log("here");
        console.log(req.body.sport + " " + req.body.matchid);
        console.log("here");
        let a = req.user.public_rooms;
        let flag = 0;
        for (let i = 0; i < a.length; i++) {
            if (a[i].room_name === req.body.room) {
                flag = 1;
                break;
            }
        }
        if (flag === 0) {
            req.user.public_rooms.push({
                room_name: req.body.room
            });
            console.log(req.user.public_rooms);
        }


        req.user.save(function (err) {
            if (err) {
                req.flash('error', "error joining room please try again");
                res.redirect("/roomassign");
            } else {
                models.User.find({}, function (error, docs) {
                    console.log(docs);
                    active_users = [];
                    for (let i = 0; i < docs.length; i++) {
                        let j = docs[i].public_rooms;
                        for (let k = 0; k < j.length; j++) {
                            if (j[k].room_name === req.body.room) {
                                active_users.push(docs[i].username);
                                break;
                            }
                        }
                    }
                    console.log(active_users);
                    res.render("chat", { user: req.user, name: req.body.room, list: active_users, room_type: "public", sport: req.body.sport, matchid: req.body.matchid });
                });


            }
        });
    } else {
        res.render("nonauthenticated");
    }
});
app.post("/createaprivateroom", function (req, res) {
    if (req.isAuthenticated()) {
        const room = new models.Privateroom({
            private_room_name: req.body.privateroom_name,
            private_room_id: generateOTP(),
            active_users: [{ user: req.user.username }]
        });
        room.save(function (err) {
            if (err) {
                req.flash("error", "error creating a room try again");
                res.redirect("/roomassign");
            } else {
                res.redirect("/joinaprivateroom/" + room.private_room_id);
            }
        })
    } else {
        res.render("nonauthenticated");
    }
});
app.get("/joinaprivateroom/:id", function (req, res) {
    if (req.isAuthenticated()) {
        models.Privateroom.findOne({ private_room_id: req.params["id"] }, function (err, room) {
            if (err) {
                req.flash("error", "error joining a room try again");
                res.redirect("/roomassign");
            } else {
                if (room === null) {
                    req.flash("error", "no such room with given id exists");
                    res.redirect("/roomassign");
                } else {
                    let arr = room.active_users;
                    active_users = []
                    for (let i = 0; i < arr.length; i++) {
                        active_users.push(arr[i].user)
                    }
                    res.render("chat", { user: req.user, name: room.private_room_name, list: active_users, room_type: "private", room_id: room.private_room_id });
                }
            }
        });

    } else {
        res.render("nonauthenticated");
    }
});
app.post("/joinaprivateroom", function (req, res) {
    if (req.isAuthenticated()) {
        res.redirect("/joinaprivateroom/" + req.body.privateroom_id)
    } else {
        res.render("nonauthenticated");
    }
});
app.get("/livescore", function (req, res) {
    if (req.isAuthenticated()) {
        cricket_live_scores = [];
        soccer_live_scores = [];
        basketball_live_scores = [];

        const cric_url = 'https://allsportsapi.com/api/cricket/?met=Livescore&APIkey=' + process.env.SPORT_API_KEY;
        request(cric_url, function (cric_error, cric_response, cric_body) {
            if (cric_response.statusCode == "200" && JSON.parse(cric_body).result !== undefined) {

                let a = JSON.parse(cric_body);
                console.log(a);
                a = a.result;
                for (let i = 0; i < a.length; i++) {
                    cricket_live_scores.push(a[i]);
                }
                console.log(cricket_live_scores);
            }

            const soccer_url = "https://apiv2.allsportsapi.com/football/?met=Livescore&APIkey=" + process.env.SPORT_API_KEY;
            request(soccer_url, function (soccer_error, soccer_response, soccer_body) {
                console.log(soccer_body);

                if (soccer_response.statusCode == "200" && JSON.parse(soccer_body).result !== undefined) {
                    let b = JSON.parse(soccer_body);
                    b = b.result;
                    console.log(b);
                    for (let j = 0; j < b.length; j++) {
                        soccer_live_scores.push(b[j]);
                    }
                    console.log(soccer_live_scores);
                }
                const basketball_url = "https://allsportsapi.com/api/basketball/?met=Livescore&APIkey=" + process.env.SPORT_API_KEY;
                request(basketball_url, function (basketball_error, basketball_response, basketball_body) {
                    console.log(basketball_body);
                    if (basketball_response.statusCode == "200" && JSON.parse(basketball_body).result !== undefined) {
                        let c = JSON.parse(basketball_body);
                        c = c.result;
                        for (let k = 0; k < c.length; k++) {
                            basketball_live_scores.push(c[k]);
                        }
                        console.log(basketball_live_scores);
                    }




                    res.render("livescores", { cricket: cricket_live_scores, soccer: soccer_live_scores, basketball: basketball_live_scores });
                });

            });

        });
    } else {
        res.render("nonauthenticated");
    }

});
app.get("/livescore/:sport/:matchid", function (req, res) {
    if (req.isAuthenticated()) {

        var url = "";
        if (req.params["sport"] == "cricket") {
            url = "https://allsportsapi.com/api/cricket/?met=Livescore&APIkey=" + process.env.SPORT_API_KEY + "&matchId=" + req.params["matchid"];
        }
        if (req.params["sport"] == "basketball") {
            url = "https://allsportsapi.com/api/basketball/?met=Livescore&APIkey=" + process.env.SPORT_API_KEY + "&matchId=" + req.params["matchid"];
        }
        if (req.params["sport"] == "football") {
            url = "https://apiv2.allsportsapi.com/football/?met=Livescore&APIkey=" + process.env.SPORT_API_KEY + "&matchId=" + req.params["matchid"];
        }

        request(url, function (error, response, body) {
            console.log(body);

            if (response.statusCode == "200" && JSON.parse(body).result !== undefined) {
                let b = JSON.parse(body);
                b = b.result;
                console.log(b);
                res.render("matchscore", { obj: b[0], sport: req.params["sport"] });
            } else {
                res.send("error loading scores");
            }
        });
    } else {
        res.render("nonauthenticated");
    }
});

function formatMessage(username, text) {
    return {
        username,
        text,
        time: moment().format('h:mm a')
    };
}
io.on("connection", socket => {
    console.log(socket);
    console.log("jdsvjsbvjdbv");
    /*socket.on("disconnect", function() {
        console.log("hi");
        console.log(socket.rooms);
        console.log(socket.username);
        let a = Array.from(socket.rooms);
        if (a.length > 1) {
            for (let i = 1; i < a.length; i++) {

                models.User.findOne({ username: socket.username }, function(err, user) {
                    let b = user.public_rooms;
                    for (let j = 0; j < b.length; j++) {
                        if (b[j].room_name === a[i]) {
                            b.splice(j, 1);
                        }
                    }
                    user.save();
                    socket.to(a[i]).emit("userdisconnected", socket.username);

                });
            }

        }

        console.log("user disconnected");

    });*/
    /*on disconnection websocket connection(between clientsocket and serversocket created to make a connection) will be breaked and socket will leave all rooms without mentioning*/
    socket.on("disconnect", function () {
        console.log(socket.username);
        console.log(socket.room);
        if (socket.room !== undefined) {
            let a = Array.from(socket.room);
            if (a.length > 1) {
                for (let i = 1; i < a.length; i++) {

                    models.User.findOne({ username: socket.username }, function (err, user) {
                        let b = user.public_rooms;
                        for (let j = 0; j < b.length; j++) {
                            if (b[j].room_name === a[i]) {
                                b.splice(j, 1);
                            }
                        }

                        user.save(function (error) {
                            console.log(user);
                            io.to(a[i]).emit("userdisconnected", socket.username);
                            io.to(a[i]).emit(
                                'message',
                                formatMessage("DISBOT", socket.username + " has left the chat ")
                            );
                        });


                    });
                }

            }
        }

        console.log("user disconnected");
    });
    socket.on("room", function (room, User, obj) {
        if (obj.room_type === "public") {
            models.User.findOne({ username: User }, function (err, user) {
                let a = user.public_rooms;
                let flag = 0;
                for (let i = 0; i < a.length; i++) {
                    if (a[i].room_name === room) {
                        flag = 1;
                        break;
                    }
                }
                if (flag === 0) {
                    user.public_rooms.push({
                        room_name: room
                    });
                }

                user.save(function (error) {
                    socket.join(room);
                });



                console.log(room);

                console.log(room);
                socket.emit('message', formatMessage("DISBOT", 'Welcome to 🏅SportTalk!'));

                // Broadcast when a user connects
                socket.to(room).emit(
                    'message',
                    formatMessage("DISBOT", user.username + ' has joined the chat')
                );

            });
        } else {
            models.Privateroom.findOne({ private_room_id: obj.room_id }, function (err, room) {
                let a = room.active_users;
                let flag = 0;
                for (let i = 0; i < a.length; i++) {
                    if (a[i].user === User) {
                        flag = 1;
                        break;
                    }
                }
                if (flag === 0) {
                    room.active_users.push({
                        user: User
                    });
                }

                room.save(function (error) {
                    socket.join(obj.room_id);
                });


                socket.emit('message', formatMessage("DISBOT", 'Welcome to 🏅SportTalk!'));

                // Broadcast when a user connects
                socket.to(obj.room_id).emit(
                    'message',
                    formatMessage("DISBOT", User + ' has joined the chat')
                );
            });
        }


    });

    socket.on("new_user", function (user, room, obj) {
        if (obj.room_type === "public") {
            socket.join(room);
            console.log("here");


            socket.username = user;
            socket.room = socket.rooms;
            users = [];

            models.User.find({}, function (error, docs) {
                console.log(docs);
                active_users = [];
                for (let i = 0; i < docs.length; i++) {
                    let j = docs[i].public_rooms;
                    for (let k = 0; k < j.length; j++) {
                        if (j[k].room_name === room) {
                            users.push(docs[i].username);
                            break;
                        }
                    }
                }
                console.log(users);
                io.to(room).emit("useradded", user, users);


            });
        } else {
            socket.join(obj.room_id);
            socket.username = user;
            socket.room = socket.rooms;
            users = [];
            models.Privateroom.findOne({ private_room_id: obj.room_id }, function (err, room) {
                console.log(room);
                let a = room.active_users;
                for (let i = 0; i < a.length; i++) {
                    users.push(a[i].user);
                }
                console.log(users);
                console.log("here");
                io.to(obj.room_id).emit("useradded", user, users);


            });



        }








    });
    socket.on('chatMessage', (msg, roomname, user) => {


        io.to(roomname).emit('message', formatMessage(user, msg));
    });
});