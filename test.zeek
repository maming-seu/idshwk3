global vecip : vector of addr;
global vecagent1 : vector of string;
global vecagent2 : vector of string;
global vecagent3 : vector of string;
global vecagentnum : vector of int;
event zeek_init()
    {
        print "zeek init";
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
        local UserAgent = "User-Agent";
        local HeaderName = "";
        local counterchar = 1;
        for (character in value)
        {
            if ( counter <= 10)
                {
                    HeaderName += character;
                }
        }
        if( HeaderName = UserAgent )
            {
                local x = -1;
                for ( ip in vecip )
                    {
                        if ( vecip[ip] == c$id$orig_h)#find same ip in vecip
                            {
                                if ( vecagentnum == 1 )
                                    {

                                    }
                                if ( vecagentnum == 2 )
                                    {

                                    }
                                if ( vecagentnum == 3 )
                                    {
                                        
                                    }
                                x = ip;
                            }
                        else#do not find the same one
                            {
                                #do nothing
                            }
                    } 
            }
        else
            {
                #do nothing;
            }
    
    }