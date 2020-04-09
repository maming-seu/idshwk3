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
        if( name == "User-Agent" )# if header's name = User-Agent
            {
                local find = 1;
                for ( ip in vecip )
                    {
                        if ( vecip[ip] == c$id$orig_h)#find same ip in vecip
                            {
                                if ( vecagentnum[ip] == 1 )
                                    {
                                        if ( vecagent1[ip] != value )
                                            {
                                                vecagent2[ip] = value;
                                                vecagentnum[ip] = 2;
                                            }
                                    }
                                if ( vecagentnum[ip] == 2 )
                                    {
                                        if (( vecagent1[ip] != value )&&( vecagent2[ip] != value))
                                            {
                                                vecagent3[ip] = value;
                                                vecagentnum[ip] = 3;
                                            }
                                    }
                                if ( vecagentnum[ip] == 3 )
                                    {
                                        #do nothing
                                    }
                            }
                        else#do not find the same one
                            {
                               find = 0;#means it is a new origin ip
                            }
                    } 
                if ( find == 0 )
                    {
                        vecip[|vecip|] = c$id$orig_h;#set the new ip and it's user-agent's name;
                        vecagent1[|vecip|-1] = value;
                        vecagentnum[|vecip|-1] = 1;
                    }
            }
        else
            {
                #do nothing;
            }
    
    }

event zeek_done()
    {
        for ( x in vecagentnum)
            {
                if ( vecagentnum[x] == 3 )
                    {
                        print fmt("%s is a proxy", vecip[x]);
                    }
            }
    }