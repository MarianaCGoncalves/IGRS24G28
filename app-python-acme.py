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

class kamailio:
    def __init__(self):
        KSR.info('===== kamailio.__init__\n')

    def child_init(self, rank):
        KSR.info('===== kamailio.child_init(%d)\n' % rank)
        return 0

    def ksr_request_route(self, msg):
        
        if  (msg.Method == "REGISTER"):
            #verifica o dominio => so acme.pt podem aceder a estes metodos
            if not self.verify_domain():
                return 1
            
            KSR.info("REGISTER R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.info("            To: " + KSR.pv.get("$tu") +
                           " Contact:"+ KSR.hdr.get("Contact") +"\n")
            KSR.registrar.save('location', 0)
            return 1

        if (msg.Method == "INVITE"): 
            #verifica o dominio => so acme.pt podem aceder a estes metodos
            if not self.verify_domain():
                return 1
                                 
            KSR.info("INVITE R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.info("        From: " + KSR.pv.get("$fu") +
                              " To:"+ KSR.pv.get("$tu") +"\n")
            
            if (KSR.pv.get("$td") == "acme.pt"):   # Check if To domain is acme.pt
                
                if (KSR.pv.get("$tu") == "sip:announce@acme.pt"):  # Special To-URI
                    
                    #caso o cliente destino aceite a chamada
                    KSR.tm.t_on_reply("ksr_onreply_route_INVITE") 
                    
                    #caso o cliente destino recuse a chamada
                    KSR.tm.t_on_failure("ksr_failure_route_INVITE")
                    
                    KSR.pv.sets("$ru", "sip:announce@127.0.0.1:5090")
                    
                    #KSR.forward()       # Forwarding using statless mode
                    KSR.tm.t_relay()    # Relaying using transaction mode
                    return 1 
                
                if (KSR.registrar.lookup("location") == 1):  # Check if registered
                    KSR.info("  lookup changed R-URI: " + KSR.pv.get("$ru") +"\n")
                    KSR.rr.record_route()  # Add Record-Route header
                    KSR.tm.t_relay()
                
                else:
                    #indica que o cliente destino nao esta registado.
                    KSR.sl.send_reply(403, "Forbidden | Recipient not registered")
            else:
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

        if (msg.Method == "BYE"):
            KSR.info("BYE R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.registrar.lookup("location")
            KSR.rr.loose_route()
            KSR.tm.t_relay()
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
            KSR.sl.send_reply(200,"Authorized")
            return True
        KSR.sl.send_reply(401,"Unauthorized")
        return False
    
    
    def ksr_onreply_route_INVITE(self, msg):
        KSR.info("===== INVITE onreply route - from kamailio python script\n")
        return 0
    
    def ksr_failure_route_INVITE(self, msg):
        KSR.info("===== INVITE failure route - from kamailio python script\n")
        
        if self.user_in_conference(msg):
            KSR.info("User busy in conference")
            KSR.pv.sets("$ru","sip:inconference@127.0.0.1:5080")
            KSR.tm.t_relay()
            
            #logica da tecla 0 aqui?

        if self.user_in_session(msg):
            KSR.info("User is currently busy in session")
            KSR.pv.sets("$ru","sip:busy@127.0.0.1:5080")
            KSR.tm.t_relay()
    
    def user_in_conference(self, msg):
        
        # se o funcionario destino estiver ocupado numa conf o pedido é reencaminhado
        # para um servidor de anuncios, durante o anuncio o chamador pode clicar na tecla "0" 
        # para se juntar a conferencia 
        
        ru = KSR.get("$ru")
        if ru == "sip:conference@127.0.0.1:5090":
            return True
        return False
    
    def user_in_session(self,msg):
        # se o funcionario destino está ocupado numa sessão, que nao uma conferencia
        # o pedido é reencaminhado para um servidor de anuncios busyann@127.0.0.1:5080
        
        if KSR.registrar.lookup("location"):
            user_status = KSR.registrar.get_status("location") #kamailio assume logo o funcionario destino
            if user_status.lower() == "busy":
                return True
            return False
        return 1
    
    def press_buton(self,msg):
        return 1