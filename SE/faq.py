from flask import Flask, jsonify, request, session 
from flask_restful import Resource, Api
from pymongo import MongoClient

# ------------------------------------------------------

# Flask app
app = Flask(__name__)
app.secret_key = 'i love white chocolate'
api = Api(app)


# ------------------------------------------------------

# Connecting to the carity_page collection
client = MongoClient('localhost', 27017)
db = client['charity_agg']


# ------------------------------------------------------

# Creating a FAQ thread

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


api.add_resource(createFAQ, '/charity/event/initQuery')

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

api.add_resource(answerFAQ, '/charity/event/answerQuery')

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

            


api.add_resource(getAnsweredFAQ, '/charity/event/getAnsweredFAQ')



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


            


api.add_resource(getunAnsweredFAQ, '/charity/event/getunAnsweredFAQ')

# ------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)

# ------------------------------------------------------
