from flask import Flask,render_template,jsonify
import bcrypt
from flask_mail import Mail, Message
from flask import request,session
from flask_restful import Resource, Api
import json
import random
import pymongo
import re
mongoConn = pymongo.MongoClient("mongodb://localhost:27017/")

db = mongoConn["charity_agg"]
mongo_user_details = db["user_details"]
mongo_charity_details = db["charity_details"]
app = Flask(__name__)
@app.after_request

def after_request(response):
  response.headers.add('Access-Control-Allow-Origin', '*')
  response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
  response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
  return response
api = Api(app)
app.secret_key = "chartiyaggregator" 

userStore = {}
loggedIn = []
linkReset = {}

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'charity.email.se@gmail.com'
app.config['MAIL_PASSWORD'] = 'charitySE123'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail=Mail(app)

class LoginPage(Resource):
    def get(self):
        return app.send_static_file('index.html')


class SignupPage(Resource):
    def get(self):
        return app.send_static_file('signup.html')

class SendMail(Resource):
    def post(self):
        requestData = json.loads(request.get_data().decode("UTF-8"))
        print(requestData)
        email = requestData["email"]
        code = random.randint(100000,999999)
        msg = Message('Confirm your Sign-up!', sender = 'charity.email.se@gmail.com', recipients = [email])
        msg.body = "Your activation code is "+ str(code)
        session[email] = code
        mail.send(msg)
        userStore[email] = requestData
        userStore[email]["password"] = bcrypt.hashpw(userStore[email]["password"].encode("utf-8"), bcrypt.gensalt())
        return "Sent"


class VerifyOTP(Resource):
    def createUser(self,key):

        if userStore[key]["role"]=="charity":
            userStore[key]["cid"] = "CHARITY"+str(random.randint(10000000,99999999))
            userStore[key]["followers"] = 0
            insertDB = mongo_charity_details.insert_one(userStore[key])
        else:
            userStore[key]["uid"] = "USER"+str(random.randint(10000000,99999999))
            insertDB = mongo_user_details.insert_one(userStore[key])
        del userStore[key]

    def post(self):
        jsonReq = json.loads(request.get_data().decode("UTF-8"))
        email = jsonReq["email"]
        otp = jsonReq["otp"]
        if(int(otp)==int(session[email])):
            session.pop(email)
            self.createUser(email)
            return "1"
        else:
            return "0"

class UpdateCharityFollowCount(Resource):

    def post(self):
        jsonReq = request.get_json(force=True)
        print(jsonReq)
        myquery = { "cid": jsonReq["CharityID"]}
        row = mongo_charity_details.find({"cid":jsonReq["CharityID"]}).limit(1)
        currFollow = row[0]["followers"] +1
        newvalues = { "$set": { "followers": currFollow }}
        updateDB = mongo_charity_details.update_one(myquery,newvalues)

    def get(self):
        row = mongo_charity_details.find({"cid":request.args["CharityID"]}).limit(1)
        return str(row[0]["followers"])

class Login(Resource):
    def post(self):
        jsonReq = json.loads(request.get_data().decode("UTF-8"))
        email = jsonReq["email"]
        password = jsonReq["password"]
        userrow = mongo_user_details.find({"email":email}).limit(1)
        charityrow = mongo_charity_details.find({"email":email}).limit(1)
        if userrow.count():
            if bcrypt.checkpw(password.encode("utf-8"), userrow[0]["password"]):
                return "Logged In-"+str(userrow[0]["uid"])
        elif charityrow.count():
            if bcrypt.checkpw(password.encode("utf-8"), charityrow[0]["password"]):
                return "Logged In-"+str(charityrow[0]["cid"])
        return "Wrong password"

class ForgotPassword(Resource):

    def post(self):
        requestData = json.loads(request.get_data().decode("UTF-8"))
        url = re.sub('[^a-zA-Z]', '', str(bcrypt.hashpw(requestData["email"].encode("utf-8"),bcrypt.gensalt())))[:30:]
        email = requestData["email"]
        linkReset[url] = email
        msg = Message('Reset password', sender = 'charity.email.se@gmail.com', recipients = [email])
        msg.body = "Click this URL to reset your password "+"http://localhost:4000/validatepassword/"+ url
        mail.send(msg)
        return "Sent"
        
class ValidateResetPassword(Resource):

    def get(self,url):
        if url in linkReset:
            return app.send_static_file('reset.html')

class SetNewPassword(Resource):

    def post(self):
        password = json.loads(request.get_data().decode("UTF-8"))["password"]
        url = json.loads(request.get_data().decode("UTF-8"))["url"]
        myquery = { "email": linkReset[url] }
        newvalues = { "$set": { "password": bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()) } }
        updateDB = mongo_user_details.update_one(myquery,newvalues)
        del linkReset[url]

class CollectCustomPageData(Resource):
    
    def post(self):
        pageData  = request.get_json(force=True) 
        if pageData["type"]=="event":
            pass
    
    def get(self):
        print(request.args)
        return "sent"

class CustomProfilePage(Resource):
    
    def get(self):
        return app.send_static_file('customize.html')
    
class EventsPage(Resource):
    
    def get(self):
        return app.send_static_file('events.html')

class createFAQ(Resource):
    def post(self):
        '''
        Expected json format:
        {
            "CharityID": 1, 
            "EventID":  "12",
            "QueryString": "Will refreshments be provided at the event?"
        }
        '''
        req = eval(request.data)
        cid = req["CharityID"]
        eid = req["EventID"]
        print(req)
        events = db["events"]
        # Check if corresponding charity and event IDs exist
        if(events.find_one({"CharityID": cid, "EventID": eid}) == None):
            return "There is no event ID %s for charity ID %s in DB"%(eid, cid), 404
        faqs = db["faqs"]
        # Check if any faqs exist for this event. If yes, get max value of ++FaqID as new FaqID
        new_faq_id = faqs.find_one({"CharityID": cid, "EventID": eid}, sort = [("FaqID", -1)])
        if(new_faq_id == None):
            new_faq_id = 0
        else:
            new_faq_id = new_faq_id["FaqID"]
            new_faq_id += 1
        query = req["QueryString"]
        faqs.insert_one({"CharityID": cid, "EventID": eid, "FaqID" : new_faq_id, "QueryString": query, "Answer" : "", "Answered":0})
        return "New FAQ Query added with FaqID %s"%(new_faq_id), 201


# ------------------------------------------------------

# Adding replies to existing thread

class answerFAQ(Resource):
    def post(self):
        '''
        Expected json format:
        {
            "CharityID": 1, 
            "EventID":  "12",
            "FaqID": 3,
            "Answer": "No, participants are kindly requested to bring their own refreshments."
        }
        '''
        req = eval(request.data)
        cid = req["CharityID"]
        eid = req["EventID"]
        fid = req["FaqID"]
        faqs = db["faqs"]
        # Check if corresponding charity, event IDs and FAQ IDs exist
        faq = faqs.find_one({"CharityID": cid, "EventID": eid, "FaqID":fid})
        if(faq == None):
            return "There is no FAQ ID %s and event ID %s for charity ID %s in DB"%(fid, eid, cid), 404
        '''Uncomment when sessions are active'''
        # if (session["logged_in"] == False):
        #     return "Not logged in", 400

        # if(session["logged_in_as"] != "Charity" or session["cid"] != cid):
        #     return "The cid does not match or you are not a charity!", 400
        
        answer = req["Answer"]
        faqs.update_one({"CharityID": cid, "EventID": eid, "FaqID":fid}, {"$set" : {"Answer" : answer}})
        faqs.update_one({"CharityID": cid, "EventID": eid, "FaqID":fid}, {"$set" : {"Answered" : 1}})

        return "New answer", 201

# ------------------------------------------------------


# Get full thread

class getAnsweredFAQ(Resource):
    def get(self):
        '''
        Expected json format:
        {
            "CharityID": 1, 
            "EventID":  "12"
        }

        returned json format:
        [
            {
                "Query": Will participants recieve certificates for finishing event?",                   
                "Answer":"Yes, they will! Register soon!"
            }
            {
                "Query": Why does this event not help cats?",                   
                "Answer":"Because dogs are better than cats"
            }
        ]
        '''
        req = eval(request.data)
        cid = req["CharityID"]
        eid = req["EventID"]
        faqs = db["faqs"]

        # Check if corresponding charity, event IDs and FAQ IDs exist
        faq = faqs.find({"CharityID": cid, "EventID": eid, "Answered": 1})
        if(faq == None):
            return "There is no answered FAQs for event ID %s for charity ID %s in DB"%(eid, cid), 204
        ret_val = []
        for i in faq:
            temp = {}
            temp["Query"] = i["QueryString"]
            temp["Answer"] = i["Answer"]
            ret_val.append(temp)            
        return ret_val, 200

class getunAnsweredFAQ(Resource):
    def get(self):
        '''
        Expected json format:
        {
            "CharityID": 1, 
            "EventID":  "12"
        }

        returned json format:
        [        
            {
                "Query":"Will participants recieve certificates for finishing event?",
                "FaqID": 2
            },  
            {
                "Query": "Why does this event not help cats?"     
                "FaqID": 2
            }      
        ]
        '''
        req = eval(request.data)
        cid = req["CharityID"]
        eid = req["EventID"]
        faqs = db["faqs"]

        # Check if corresponding charity, event IDs and FAQ IDs exist
        faq = faqs.find({"CharityID": cid, "EventID": eid, "Answered": 0})
        if(faq == None):
            return "There is no answered FAQs for event ID %s for charity ID %s in DB"%(eid, cid), 204
        ret_val = []
        for i in faq:
            temp = {}
            temp["Query"] = i["QueryString"]
            temp["FaqID"] = i["FaqID"]
            ret_val.append(temp)            
        return ret_val, 200

api.add_resource(LoginPage, '/login')
api.add_resource(SignupPage, '/signup')
api.add_resource(CustomProfilePage, '/profile')
api.add_resource(EventsPage, '/events')
api.add_resource(SendMail, '/sendMail')
api.add_resource(VerifyOTP, '/verifyotp')
api.add_resource(Login, '/login/senddata')
api.add_resource(ForgotPassword, '/passwordreset')
api.add_resource(ValidateResetPassword, '/validatepassword/<url>')
api.add_resource(SetNewPassword, '/resetpassword')
api.add_resource(CollectCustomPageData, '/customdata')
api.add_resource(getunAnsweredFAQ, '/charity/event/getunAnsweredFAQ')
api.add_resource(getAnsweredFAQ, '/charity/event/getAnsweredFAQ')
api.add_resource(answerFAQ, '/charity/event/answerQuery')
api.add_resource(createFAQ, '/charity/event/initQuery')
api.add_resource(UpdateCharityFollowCount, '/updatefollow')

if __name__ == '__main__':
    app.run(port=4000,debug=True)
