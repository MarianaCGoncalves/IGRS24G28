import sys
import KSR as KSR

def dumpObj(obj):           # List all obj attributes and methods
    for attr in dir(obj):
        KSR.info("obj attr = %s" % attr)
        if (attr != "Status"):
            KSR.info(" type = %s\n" % type(getattr(obj, attr)))
        else:
            KSR.info("\n")
    return 1

def mod_init():
    KSR.info("===== from Python mod init\n")
    return kamailio()

#user_status = {"alice@acme.pt":"FREE","bob@acme.pt":"FREE"}

class kamailio:
    def __init__(self):
        KSR.info('===== kamailio.__init__\n')
        self.userStatus = {}

    def child_init(self, rank):
        KSR.info('===== kamailio.child_init(%d)\n' % rank)
        return 0

    def ksr_request_route(self, msg):
        
        domain_status = self.verify_domain()
        
        if domain_status == "Forbidden":
                KSR.sl.send_reply(403,"Forbidden")
                return 1
        if  (msg.Method == "REGISTER"):
            #verifica o dominio => so acme.pt podem aceder a estes metodos
            
            
            KSR.info("REGISTER R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.info("            To: " + KSR.pv.get("$tu") +
                           " Contact:"+ KSR.hdr.get("Contact") +"\n")
            KSR.registrar.save('location', 0)
            return 1

        if (msg.Method == "INVITE"): 
            
            #user_status = 'user_status.txt'
            #global user_status
            
            KSR.info("INVITE R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.info("        From: " + KSR.pv.get("$fu") +
                              " To:"+ KSR.pv.get("$tu") +"\n")
            
            if (KSR.pv.get("$td") == "acme.pt"):   # Check if To domain is acme.pt
                
                #for user, status in user_status.items(): KSR.info(f"User: {user}, Status: {status}")
                
                if (KSR.pv.get("$tu") == "sip:conference@acme.pt"): # Special To-URI
                    user_status = self.userStatus
                    KSR.info("Entrou na condição de conferência\n")
                    
                    #caso o cliente destino aceite a chamada
                    KSR.tm.t_on_reply("ksr_onreply_route_INVITE") 
                    
                    #caso o cliente destino recuse a chamada
                    KSR.tm.t_on_failure("ksr_failure_route_INVITE")
                    
                    #pickle_file= open("user_status.txt", 'r')
                    #user_status_list = pickle.load(pickle_file)
                    
                    KSR.pv.sets("$ru","sip:conference@acme.pt:5090")
                    
                    caller_id = KSR.pv.get("$fu")
                    
                    
                    #KSR.info("CALLER_ID: "+caller_id)
                    #caller_status = user_status.get(caller_id)
                    
                    user_status[caller_id] = "BUSY_CONFERENCE"
                    
                    #KSR.forward()       # Forwarding using statless mode
                    for user, status in user_status.items(): KSR.info(f"User: {user}, Status: {status}")
                    KSR.tm.t_relay()    # Relaying using transaction mode
                    
                else:
                    if not self.verify_registry():
                        KSR.sl.send_reply(404, "Not Found")
                    #pickle_file= open("user_status.txt", 'r')
                    #user_status_list = pickle.load(pickle_file)
                    #KSR.info("CALLER_ID: "+caller_id)
                    #vai buscar o estado de quem está a ser chamado.
                    KSR.info("Entrou na condição de chamada acme.pt\n")
                    user_status = self.userStatus
                    for user, status in user_status.items(): KSR.info(f"User: {user}, Status: {status}")
                    
                    caller_id = KSR.pv.get("$fu")
                    called_id = KSR.pv.get("$tu")
                    
                    called_status = user_status.get(called_id)
                    KSR.info(f"CALLED STATUS: {called_status}")
                    
                    if called_status == "BUSY_CONFERENCE":
                        KSR.pv.sets("$ru","sip:inconference@acme.pt:5080")
                        #KSR.tm.t_relay()
                    
                    elif called_status == "BUSY": 
                        KSR.pv.sets("$ru","sip:busyann@acme.pt:5080")
                    
                    else:
                        user_status[caller_id] = "BUSY"
                    
                    
                    KSR.tm.t_relay()
                        
                    #caso o cliente destino aceite a chamada
                    #KSR.tm.t_on_reply("ksr_onreply_route_INVITE") 
                    
                    #caso o cliente destino recuse a chamada
                    #KSR.tm.t_on_failure("ksr_failure_route_INVITE")
                    
                    #KSR.rr.record_route()    
                    
                    #pickle_file.close()
                
                #KSR.tm.t_relay()
                for user, status in user_status.items(): KSR.info(f"User: {user}, Status: {status}")
            else:
                KSR.tm.t_on_reply("ksr_onreply_route_INVITE") 
                KSR.tm.t_on_failure("ksr_failure_route_INVITE")
                
                KSR.rr.record_route()
                KSR.tm.t_relay()
            return 1

        if (msg.Method == "ACK"):
            KSR.info("ACK R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.rr.loose_route()
            KSR.tm.t_relay()
            return 1

        if (msg.Method == "CANCEL"):
            KSR.info("CANCEL R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.registrar.lookup("location")
            KSR.tm.t_relay()
            return 1
            
#começo da lógica do reencaminhamento com o botão.
        
        #if (msg.Method == "INFO"):
            #KSR.info("INFO R-URI: " + KSR.pv.get("$ru") + "\n")
            #KSR.rr.loose_route()
            #KSR.pv.sets("$ru","sip:conference@acme.pt:5090")
            #KSR.tm.t_relay()
            
            #return 1

        if (msg.Method == "BYE"):
            KSR.info("BYE R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.registrar.lookup("location")
            KSR.rr.loose_route()
            KSR.tm.t_relay()
            
            caller_id = KSR.pv.get("$fu")
            called_id = KSR.pv.get("$tu")
            caller_status = user_status.get(caller_id)
            called_status = user_status.get(called_id)
            
            if (caller_status == "BUSY" or caller_status == "BUSY_CONFERENCE"):
                user_status[caller_id] = "FREE"
                user_status[called_id] = "FREE"
                
            # Additional behaviour for BYE - sending a MESSAGE Request
            if (KSR.pv.get("$fd") == "acme.pt"):
                KSR.pv.sets("$uac_req(method)", "MESSAGE")
                KSR.pv.sets("$uac_req(ruri)", KSR.pv.get("$fu")) # Send to ender
                KSR.pv.sets("$uac_req(turi)", KSR.pv.get("$fu"))
                KSR.pv.sets("$uac_req(furi)", "sip:kamailio@acme.pt")
                KSR.pv.sets("$uac_req(callid)", KSR.pv.get("$ci")) # Keep the Call-ID
                msg = "You have ended a call"
                hdr = "Content-Type: text/plain\r\n" # More headers can be added
                KSR.pv.sets("$uac_req(hdrs)", hdr)
                KSR.pv.sets("$uac_req(body)", msg)
                KSR.uac.uac_req_send()
            return 1

        if (msg.Method == "MESSAGE"):
            KSR.info("MESSAGE R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.info("        From: " + KSR.pv.get("$fu") + " To:"+ KSR.pv.get("$tu") +"\n")
            if (KSR.pv.get("$rd") == "acme.pt"):
                if (KSR.registrar.lookup("location") == 1):
                    KSR.info("  lookup changed R-URI: " + KSR.pv.get("$ru") +"\n")
                    KSR.tm.t_relay()
                else:
                    KSR.sl.send_reply(404, "Not found")
            else:
                KSR.rr.loose_route()
                KSR.tm.t_relay()
            return 1

    def ksr_reply_route(self, msg):
        KSR.info("===== response - from kamailio python script\n")
        KSR.info("      Status is:"+ str(KSR.pv.get("$rs")) + "\n");
        return 1

    def ksr_onsend_route(self, msg):
        KSR.info("===== onsend route - from kamailio python script\n")
        KSR.info("      %s\n" %(msg.Type))
        return 1
    
    def verify_pin(self,pin):
        pin = KSR.pv.get("$rb")
        if pin == "0000":
            KSR.sl.send_reply(200,"OK")
            return True
        return False
    
    def verify_domain(self):
        domain = KSR.pv.get("$fd").split("@")[-1] #obter sempre a ultima parte da string
        if domain == "acme.pt":
            #KSR.sl.send_reply(200,"OK")
            return "OK"
        #KSR.sl.send_reply(403,"Forbidden")
        return "Forbidden"
    
    
    def ksr_onreply_route_INVITE(self, msg):
        KSR.info("===== INVITE onreply route - from kamailio python script\n")
        return 0
    
    def ksr_failure_route_INVITE(self, msg):
        KSR.info("===== INVITE failure route - from kamailio python script\n")
        #if KSR.pv.get("$rs") == 486:
            #KSR.pv.sets("$ru","sip:conference@127.0.0.1:5080")
            #KSR.tm.t_relay()
            #return 1
        #else:
            #KSR.info("Couldn't redirect to announce server.")
        return 0
    
    def press_buton(self,msg):
        return 1
    
    def verify_registry(self):
        if (KSR.registrar.lookup("location") == 1):  # Check if registered
            KSR.info("  lookup changed R-URI: " + KSR.pv.get("$ru") +"\n")
            KSR.rr.record_route()  # Add Record-Route header
            return True
            
        else:
            #indica que o cliente destino nao esta registado.
            #KSR.sl.send_reply(403, "Forbidden | Recipient not registered")
            return False
