<%@ page import="java.util.*" %>

<%@ page import="com.cloud.utils.*" %>

<%
    Locale browserLocale = request.getLocale();
    CloudResourceBundle t = CloudResourceBundle.getBundle("resources/resource", browserLocale);
%>
<%
long milliseconds = new Date().getTime();
%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta http-equiv='cache-control' content='no-cache'>
    <meta http-equiv='expires' content='0'>
    <meta http-equiv='pragma' content='no-cache'>
    <meta name="version" content="1.9.1.2010-08-25T16:16:56Z" />
    <link rel="stylesheet" href="css/jquery-ui.custom.css" type="text/css" />
    <link rel="stylesheet" href="css/logger.css" type="text/css" />
    <link rel="stylesheet" href="css/main.css" type="text/css" />

	<!-- Common libraries -->
    <script type="text/javascript" src="scripts/jquery.min.js"></script>
    <script type="text/javascript" src="scripts/jquery-ui.custom.min.js"></script>
    <script type="text/javascript" src="scripts/date.js"></script>
    <script type="text/javascript" src="scripts/jquery.cookies.js"></script>
    <script type="text/javascript" src="scripts/jquery.timers.js"></script>
    <script type="text/javascript" src="scripts/jquery.md5.js"></script>

    <!-- cloud.com scripts -->
    <script type="text/javascript" src="scripts/cloud.logger.js?t=<%=milliseconds%>"></script>
	<script type="text/javascript" src="scripts/cloud.core.callbacks.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.js?t=<%=milliseconds%>"></script>
	<script type="text/javascript" src="scripts/cloud.core.init.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.instance.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.event.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.alert.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.account.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.volume.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.snapshot.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.ipaddress.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.template.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.iso.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.router.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.dashboard.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.domain.js?t=<%=milliseconds%>"></script>    
    <script type="text/javascript" src="scripts/cloud.core.serviceoffering.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.diskoffering.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.globalsetting.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.resource.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.zone.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.pod.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.cluster.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.host.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.primarystorage.js?t=<%=milliseconds%>"></script>
    <script type="text/javascript" src="scripts/cloud.core.systemvm.js?t=<%=milliseconds%>"></script>
	
	<!-- Favicon -->
	<link rel="shortcut icon" href="favicon.ico" type="image/x-icon" />

    <title>Cloud.com CloudStack Management Console</title>
</head>
<body>
	<!-- Main Login Dialog (begin)-->
	<div id="login_wrapper" style="display:none">
    	<div class="login_main">
        	<div class="login_logopanel">
            	<div class="login_logobox"></div>
            </div>
            <div class="main_loginbox">
            	<div class="main_loginbox_top"></div>
                <div class="main_loginbox_mid">
                	<div class="login_contentbox">
                    	<div class="login_contentbox_title">
                        	<h1>Welcome to Management Console &hellip;</h1>
                        </div>
                        
                        <div class="login_formbox">
                        	<form id="loginForm" action="#" method="post" name="loginForm">
                            	<ol>
                                	<li>
                                    	<label for="user_name">Username: </label>
                                        <div class="login_formbox_textbg">
                                        	<input id="account_username" class="text" type="text" name="account_username" AUTOCOMPLETE="off"/>
                                        </div>
                                    </li>
                                    
                                    <li>
                                    	<label for="user_name">Password: </label>
                                        <div class="login_formbox_textbg">
                                        	<input id="account_password" class="text" type="password" name="account_password" AUTOCOMPLETE="off"/>
                                        </div>
                                    </li>
                                    
                                    <li>
                                    	<label for="user_name">Domain: </label>
                                        <div class="login_formbox_textbg">
                                        	<input id="account_domain" class="text" type="text" name="account_domain" />
                                        </div>
                                    </li>
                                </ol>
                                <div class="loginbutton_box">
                                	<div class="login_button" id="loginbutton" >Login</div>
                                </div>
                            </form>
                            
                            <div class="error_box" id="login_error" style="display:none;">
                            	<p>Your username/password does not match our records.</p>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="main_loginbox_bot"></div>
            </div>
        </div>
    </div>
	<!-- Main Login Dialog (end)-->

	<!-- Main Console -->
    <div id="overlay_black" style="display: none">
    </div>
    <div id="main" style="display: none">
        <div id="main_header">
            <div class="header_left">
                <div class="logo">
                </div>
                <div class="mgmtconsole_logo">
                </div>
            </div>
            <div class="header_right">
                <div class="userlinks">
                    <p>
                        Welcome <span id="main_username">Anonymous</span>, <a href="#" id="main_logout">Logout</a>
                    </p>
                </div>
            </div>
        </div>
        <div id="main_contentpanel">
            <div class="right_panel">
                <div id="contentwrapper">
                    <!-- Action Panel starts here-->
                    <div class="actionpanel">
                        <div class="searchpanel" id="search_panel">
                            <form method="post" action="#">
                            <ol>
                                <li>
                                    <div class="search_textbg">
                                        <input class="text" type="text" name="search_input" />
                                        <div class="search_closebutton" style="display: none;">
                                        </div>
                                    </div>
                                </li>
                            </ol>
                            </form>
                            <a href="#">
                                <%=t.t("advanced")%></a>
                            <div class="adv_searchpopup" id="adv_search_dialog" style="display: none;">
                                <div class="adv_searchformbox">
                                    <h3>
                                        Advance Search</h3>
                                    <a id="advanced_search_close" href="#">Close </a>
                                    <form action="#" method="post">
                                    <ol style="margin-top: 8px;">
                                        <li>
                                            <label for="filter">
                                                Name:</label>
                                            <input class="text" type="text" name="adv_search_name" id="adv_search_name" />
                                        </li>
                                        <li>
                                            <label for="filter">
                                                Status:</label>
                                            <select class="select" id="adv_search_state">
                                                <option value=""></option>
                                                <option value="Creating">Creating</option>
                                                <option value="Starting">Starting</option>
                                                <option value="Running">Running</option>
                                                <option value="Stopping">Stopping</option>
                                                <option value="Stopped">Stopped</option>
                                                <option value="Destroyed">Destroyed</option>
                                                <option value="Expunging">Expunging</option>
                                                <option value="Migrating">Migrating</option>
                                                <option value="Error">Error</option>
                                                <option value="Unknown">Unknown</option>
                                            </select>
                                        </li>
                                        <li>
                                            <label for="filter">
                                                Zone:</label>
                                            <select class="select" id="adv_search_zone">
                                            </select>
                                        </li>
                                    </ol>
                                    </form>
                                    <div class="adv_search_actionbox">
                                        <div class="adv_searchpopup_button" id="adv_search_button">
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="actionpanel_button_wrapper" id="midmenu_action_link" style="position: relative;
                            display: none">
                            <div class="actionpanel_button">
                                <div class="actionpanel_button_icons">
                                    <img src="images/actions_actionicon.png" alt="Add" /></div>
                                <div class="actionpanel_button_links">
                                    <%=t.t("actions")%></div>
                                <div class="action_ddarrow">
                                </div>
                            </div>
                            <div class="actionsdropdown_box" id="action_menu" style="display: none;">
                                <ul class="actionsdropdown_boxlist" style="width: 97px;" id="action_list">
                                </ul>
                            </div>
                        </div>
                        <div class="actionpanel_button_wrapper" id="midmenu_add_link" style="display: none;">
                            <div class="actionpanel_button">
                                <div class="actionpanel_button_icons">
                                    <img src="images/addvm_actionicon.png" alt="Add" /></div>
                                <div class="actionpanel_button_links" id="label">
                                    <%=t.t("add")%></div>
                            </div>
                        </div>
                        <div class="actionpanel_button_wrapper" id="midmenu_add2_link" style="display: none;">
                            <div class="actionpanel_button">
                                <div class="actionpanel_button_icons">
                                    <img src="images/addvm_actionicon.png" alt="Add" /></div>
                                <div class="actionpanel_button_links" id="label">
                                    <%=t.t("add")%></div>
                            </div>
                        </div>
                        <div class="actionpanel_button_wrapper" id="midmenu_add3_link" style="display: none;">
                            <div class="actionpanel_button">
                                <div class="actionpanel_button_icons">
                                    <img src="images/addvm_actionicon.png" alt="Add" /></div>
                                <div class="actionpanel_button_links" id="label">
                                    <%=t.t("add")%></div>
                            </div>
                        </div>
                        <div class="actionpanel_button_wrapper" id="midmenu_startvm_link" style="display: none;">
                            <div class="actionpanel_button">
                                <div class="actionpanel_button_icons">
                                    <img src="images/startvm_actionicon.png" alt="Start VM" /></div>
                                <div class="actionpanel_button_links">
                                    Start VM</div>
                            </div>
                        </div>
                        <div class="actionpanel_button_wrapper" id="midmenu_stopvm_link" style="display: none;">
                            <div class="actionpanel_button">
                                <div class="actionpanel_button_icons">
                                    <img src="images/stopvm_actionicon.png" alt="Stop VM" /></div>
                                <div class="actionpanel_button_links">
                                    Stop VM</div>
                            </div>
                        </div>
                        <div class="actionpanel_button_wrapper" id="midmenu_rebootvm_link" style="display: none;">
                            <div class="actionpanel_button">
                                <div class="actionpanel_button_icons">
                                    <img src="images/rebootvm_actionicon.png" alt="Reboot VM" /></div>
                                <div class="actionpanel_button_links">
                                    Reboot VM</div>
                            </div>
                        </div>
                        <div class="actionpanel_button_wrapper" id="midmenu_destroyvm_link" style="display: none;">
                            <div class="actionpanel_button">
                                <div class="actionpanel_button_icons">
                                    <img src="images/destroyvm_actionicon.png" alt="Destroy VM" /></div>
                                <div class="actionpanel_button_links">
                                    Destroy VM</div>
                            </div>
                        </div>
                        <div class="actionpanel_button_wrapper" id="help_link" style="display: block; border:none; float: right;
                        position: relative;">
                            <div class="actionpanel_button" id="help_button">
                                <div class="actionpanel_button_icons">
                                    <img src="images/help_actionicon.png" alt="Help" /></div>
                                <div class="actionpanel_button_links">
                                    <%=t.t("help")%></div>
                            </div>
                        </div>
                        
                        <div class="actionpanel_button_wrapper" id="help_link" style="display: block; border:none; float: right;
                        position: relative;">
                            <div class="actionpanel_button" id="help_button">
                                <div class="actionpanel_button_icons">
                                    <img src="images/refresh_actionicon.png" alt="Refresh" /></div>
                                <div class="actionpanel_button_links">
                                    Refresh</div>
                            </div>
                        </div>
                        
						<div class="help_dropdown_box" id="help_dropdown_dialog" style="display:none;">
                            	<div class="help_dropdown_box_titlebox">
                                	<h2>Help</h2>
                                    <a id="help_dropdown_close" href="#"> Close</a>
                                </div>
                                
                                <div class="help_dropdown_box_textbox" id="help_dropdown_body">
									<a id="help_top" name="help_top"></a>
                                	<ul>
                                    	<li><a href="#topic1">Topic 1</a></li>
                                        <li><a href="#topic2">Topic 2</a></li>
                                        <li><a href="#topic3">Topic 3</a></li>
                                    </ul>
                                    
                                    
                                    <h3>Topic 1<a id="topic1" name="topic1"></a>&nbsp;<a href="#help_top">Top</a></h3>
                                	<p>Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. </p>
                                    
                                   
                                    <h3>Topic 2 <a id="topic2" name="topic2"></a></h3>
                                	<p>Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. </p><p>It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.</p>
                                    
                                    <h3>Topic 3<a id="topic3" name="topic3"></a></h3>
                                	<p>Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. </p><p>It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.</p>
                                </div>
                            </div>
                    </div>
                    <!-- Action Panel ends here-->
                    <!-- Right Panel starts here-->
                    <div class="main_contentarea" id="right_panel">
                    </div>
                    <div class="midmenu_navigationbox" id="middle_menu_pagination">
                        <div class="midmenu_prevbutton">
                        </div>
                        <div class="midmenu_nextbutton">
                        </div>
                    </div>
                    <!-- Right Panel ends here-->
                </div>
                <!-- Mid Menu starts here-->
                <div class="midmenu_panel" id="middle_menu">
                    <div class="midmenu_box" id="midmenu_box">
                        <div id="midmenu_spinning_wheel" class="midmenu_mainloaderbox" style="display: none;">
                            <div class="midmenu_mainloader_animatedicon">
                            </div>
                            <p>
                                Loading &hellip;</p>
                        </div>
                        <div id="midmenu_container">                            
                        </div>
                    </div>
                </div>
                <!-- Mid Menu ends here-->
            </div>
        </div>
        <!-- Left Menu starts here-->
        <div class="leftmenu_panel">
            <div class="leftmenu_box" id="leftmenu_container">     
                <div class="leftmenu_list">
                    <div class="leftmenu_content_flevel" id="leftmenu_dashboard">
                        <div class="leftmenu_firstindent">
                            <div class="leftmenu_list_icons">
                                <img src="images/leftmenu_dashboardicon.png" alt="Dashboard" /></div>
                            <%=t.t("dashboard")%>
                        </div>
                    </div>
                    
                </div>
                <div class="leftmenu_list">
                    <div class="leftmenu_content_flevel" id="leftmenu_instances">
                        <div class="leftmenu_firstindent">
                            <div class="leftmenu_arrows_firstlevel_open" id="expandable_first_level_arrow" style="display:none;"></div>
                            <div class="leftmenu_list_icons">
                                <img src="images/instance_leftmenuicon.png" alt="Instance" /></div>
                            <%=t.t("instance")%>
                        </div>
                    </div>
                    
                    <div id="leftmenu_instance_expandedbox" class="leftmenu_expandedbox" style="display: none">
						<div class="leftmenu_expandedlist" id="leftmenu_instances_my_instances_container" style="display:none">
							<div class="leftmenu_content" id="leftmenu_instances_my_instances">
								<div class="leftmenu_secondindent">
									<div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
									</div>
									<span id="label">My Instances</span>
								</div>
							</div>
						</div>
						<div class="leftmenu_expandedlist" id="leftmenu_instances_all_instances_container" style="display:none">
							<div class="leftmenu_content" id="leftmenu_instances_all_instances">
								<div class="leftmenu_secondindent">
									<div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
									</div>
									<span id="label">All Instances</span>
								</div>
							</div>
						</div>
						<div class="leftmenu_expandedlist" id="leftmenu_instances_running_instances_container" style="display:none">
							<div class="leftmenu_content" id="leftmenu_instances_running_instances">
								<div class="leftmenu_secondindent">
									<div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
									</div>
									<span id="label">Running Instances</span>
								</div>
							</div>
						</div>
						<div class="leftmenu_expandedlist" id="leftmenu_instances_stopped_instances_container" style="display:none">
							<div class="leftmenu_content" id="leftmenu_instances_stopped_instances">
								<div class="leftmenu_secondindent">
									<div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
									</div>
									<span id="label">Stopped Instances</span>
								</div>
							</div>
						</div>
						<div class="leftmenu_expandedlist" id="leftmenu_instances_destroyed_instances_container" style="display:none">
							<div class="leftmenu_content" id="leftmenu_instances_destroyed_instances">
								<div class="leftmenu_secondindent">
									<div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
									</div>
									<span id="label">Destroyed Instances</span>
								</div>
							</div>
						</div>
                    </div>

                </div>
                <div class="leftmenu_list">
                    <div class="leftmenu_content_flevel" id="leftmenu_storage">
                        <div class="leftmenu_firstindent">
                            <div class="leftmenu_arrows_firstlevel_open" id="expandable_first_level_arrow" style="display:none;"></div>
                            <div class="leftmenu_list_icons">
                                <img src="images/storage_leftmenuicon.png" alt="Storage" /></div>
                            <%=t.t("storage")%>
                        </div>
                    </div>
                    <div class="leftmenu_expandedbox" style="display: none">
                        <div class="leftmenu_expandedlist">
                            <div class="leftmenu_content" id="leftmenu_volume">
                                <div class="leftmenu_secondindent">
                                    
                                
                                   	<div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                    </div>
                                      
                                    <%=t.t("volume")%>
                                </div>
                            </div>
                        </div>
                        <div class="leftmenu_expandedlist">
                            <div class="leftmenu_content" id="leftmenu_snapshot">
                                <div class="leftmenu_secondindent">
                                	  <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                            </div>
                                   
                                    <%=t.t("snapshot")%>
                                </div>
                            </div>
                        </div>
                    </div>
                </div> 
                <div class="leftmenu_list">
                    <div class="leftmenu_content_flevel" id="leftmenu_network">
                        <div class="leftmenu_firstindent">
                            <div class="leftmenu_arrows_firstlevel_open" id="expandable_first_level_arrow" style="display:none;"></div>
                            <div class="leftmenu_list_icons">
                                <img src="images/network_leftmenuicon.png" alt="Network" /></div>
                            <%=t.t("Network")%>
                        </div>
                    </div>
                    <div class="leftmenu_expandedbox" style="display: none">
                        <div class="leftmenu_expandedlist">
                            <div class="leftmenu_content" id="leftmenu_ip">
                                <div class="leftmenu_secondindent">
                                   	<div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                    </div>
                                    
                                    <%=t.t("ip.address")%>
                                </div>
                            </div>
                        </div>                        
                    </div>
                </div>  
                <div class="leftmenu_list">
                    <div class="leftmenu_content_flevel" id="leftmenu_templates">
                        <div class="leftmenu_firstindent">
                            <div class="leftmenu_arrows_firstlevel_open" id="expandable_first_level_arrow" style="display:none;"></div>
                            <div class="leftmenu_list_icons">
                                <img src="images/templates_leftmenuicon.png" alt="Template" /></div>
                            <%=t.t("template")%>
                        </div>
                    </div>
                    <div class="leftmenu_expandedbox" style="display: none">
                        <div id="leftmenu_itemplate_filter">
                            <div class="leftmenu_content" id="leftmenu_template_filter_header">
                                <div class="leftmenu_secondindent">
                                    <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                    </div>
                                    
                                    <%=t.t("template")%>
                                </div>
                            </div>
                            <div id="leftmenu_template_filter_container">
                                <div class="leftmenu_expandedlist">
                                    <div class="leftmenu_content" id="leftmenu_submenu_my_template">
                                        <div class="leftmenu_thirdindent">
                                            <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                            </div>
                                            
                                            <div>
                                                <%=t.t("my.template")%></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="leftmenu_expandedlist">
                                    <div class="leftmenu_content" id="leftmenu_submenu_featured_template">
                                        <div class="leftmenu_thirdindent">
                                            <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                            </div>
                                          
                                            <div>
                                                <%=t.t("featured.template")%></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="leftmenu_expandedlist">
                                    <div class="leftmenu_content" id="leftmenu_submenu_community_template">
                                        <div class="leftmenu_thirdindent">
                                            <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                            </div>
                                            
                                            <div>
                                                <%=t.t("community.template")%></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div id="leftmenu_iso_filter">
                            <div class="leftmenu_content" id="leftmenu_iso_filter_header">
                                <div class="leftmenu_secondindent">
                                    <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                    </div>
                                    
                                    <%=t.t("iso")%>
                                </div>
                            </div>
                            <div id="leftmenu_iso_filter_container">
                                <div class="leftmenu_expandedlist">
                                    <div class="leftmenu_content" id="leftmenu_submenu_my_iso">
                                        <div class="leftmenu_thirdindent">
                                            <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                            </div>
                                            
                                            <div>
                                                <%=t.t("my.iso")%></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="leftmenu_expandedlist">
                                    <div class="leftmenu_content" id="leftmenu_submenu_featured_iso">
                                        <div class="leftmenu_thirdindent">
                                            <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                            </div>
                                            
                                            <div>
                                                <%=t.t("featured.iso")%></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="leftmenu_expandedlist">
                                    <div class="leftmenu_content" id="leftmenu_submenu_community_iso">
                                        <div class="leftmenu_thirdindent">
                                            <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                            </div>
                                            
                                            <div>
                                                <%=t.t("community.iso")%></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>  
                <div class="leftmenu_list">
                    <div class="leftmenu_content_flevel" id="leftmenu_account" style="display: none">
                        <div class="leftmenu_firstindent">
                            <!-- <div class="leftmenu_arrows_firstlevel_open" id="expandable_first_level_arrow" style="display:none;"></div> -->
                            <div class="leftmenu_list_icons">
                                <img src="images/accounts_leftmenuicon.png" alt="Account" /></div>
                            <%=t.t("account")%>
                        </div>
                    </div>
                    
                </div>                
                <div class="leftmenu_list">
                    <div class="leftmenu_content_flevel" id="leftmenu_domain" style="display: none">
                        <div class="leftmenu_firstindent">
                            <div class="leftmenu_arrows_firstlevel_open" id="expandable_first_level_arrow" style="display:none;"></div>
                            <div class="leftmenu_list_icons">
                                <img src="images/domain_leftmenuicon.png" alt="Domain" /></div>
                            <%=t.t("domain")%>
                        </div>
                    </div>
                    <div class="leftmenu_expandedbox" style="display: none">
                    		<div id="loading_container" class="leftmenu_loadingbox" style="display: none;">
                                <div class="leftmenu_loader">
                                </div>
                                <p>
                                    Loading &hellip;
                                </p>
                        </div>
                        <div id="leftmenu_domain_tree">
                            
                            <div id="tree_container" class="leftmenu_expandedlist">
                            </div>
                        </div>  
                    </div>
                </div>
                <div class="leftmenu_list">
                    <div class="leftmenu_content_flevel" id="leftmenu_events">
                        <div class="leftmenu_firstindent">
                             <div class="leftmenu_arrows_firstlevel_open" id="expandable_first_level_arrow" style="display:none;"></div>
                            <div class="leftmenu_list_icons">
                                <img src="images/events_leftmenuicon.png" alt="Event" /></div>
                            <%=t.t("event")%>
                        </div>
                    </div>
                    <div class="leftmenu_expandedbox" style="display: none">
                        <div class="leftmenu_expandedlist">
                            <div class="leftmenu_content" id="leftmenu_event">
                                <div class="leftmenu_secondindent">
                                    <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                    </div>
                                    
                                    <%=t.t("event")%>
                                </div>
                            </div>
                        </div>
                        <div class="leftmenu_expandedlist" id="leftmenu_alert_container" style="display: none">
                            <div class="leftmenu_content" id="leftmenu_alert">
                                <div class="leftmenu_secondindent">
                                    <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                    </div>
                                    
                                    <%=t.t("alert")%>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="leftmenu_list">
                    <div class="leftmenu_content_flevel" id="leftmenu_system" style="display: none">
                        <div class="leftmenu_firstindent">
                            <div class="leftmenu_arrows_firstlevel_open" id="expandable_first_level_arrow" style="display:none;"></div>
                            <div class="leftmenu_list_icons">
                                <img src="images/configuration_leftmenuicon.png" alt="System" /></div>
                            <%=t.t("system")%>
                        </div>
                    </div>
                    <div class="leftmenu_expandedbox" style="display: none">                                                          
                        <div class="leftmenu_expandedlist">
                            <div class="leftmenu_content" style="border-bottom: 1px dashed b4c8d6;" id="leftmenu_service_offering">
                                <div class="leftmenu_secondindent">
                                    <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                    </div>
                                    
                                    <%=t.t("service.offerings")%>
                                </div>
                            </div>
                        </div>
                        <div class="leftmenu_expandedlist">
                            <div class="leftmenu_content" id="leftmenu_disk_offering">
                                <div class="leftmenu_secondindent">
                                    <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                    </div>
                                    
                                    <%=t.t("disk.offerings")%>
                                </div>
                            </div>
                        </div>
                        <div class="leftmenu_expandedlist">
                            <div class="leftmenu_content" id="leftmenu_global_setting">
                                <div class="leftmenu_secondindent">
                                    <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                    </div>
                                    
                                    <%=t.t("global.settings")%>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                
                <div class="leftmenu_list">
                    <div class="leftmenu_content_flevel" id="leftmenu_resources" style="display: none">
                        <div class="leftmenu_firstindent">
                            <div class="leftmenu_arrows_firstlevel_open" id="expandable_first_level_arrow" style="display:none;"></div>
                            <div class="leftmenu_list_icons">
                                <img src="images/resource_leftmenuicon.png" alt="resources" /></div>
                            <%=t.t("resources")%>
                        </div>
                    </div>
                    <div class="leftmenu_expandedbox" style="display: none">
                        <div class="leftmenu_expandedlist">
                            <div class="leftmenu_content" id="leftmenu_physical_resource">
                                <div class="leftmenu_secondindent">
                                    <div class="leftmenu_arrows expanded_close" id="physical_resource_arrow">
                                    </div>
                                   
                                    <%=t.t("physical.resources")%>
                                </div>
                            </div>
                        </div>
                        
                        <div id="leftmenu_zone_tree">
                        	<div id="loading_container" class="leftmenu_loadingbox" style="display:none;">
                                <div class="leftmenu_loader"></div>
                                <p> Loading &hellip; </p>
                            </div>
						    <div id="tree_container"></div>
                        </div>              

						<div>
                            <div class="leftmenu_content">
                                <div class="leftmenu_secondindent">
                                    <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                    </div>
                                    
                                    <%=t.t("virtual.resources")%>
                                </div>
                            </div>
                            <div>
                                <div class="leftmenu_expandedlist">
                                    <div class="leftmenu_content" id="leftmenu_submenu_virtual_router">
                                        <div class="leftmenu_thirdindent">
                                            <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                            </div>
                                            
                                            <div>
                                                <%=t.t("virtual.router")%></div>
                                        </div>
                                    </div>
                                </div>
                                <div class="leftmenu_expandedlist">
                                    <div class="leftmenu_content" id="leftmenu_submenu_systemvm">
                                        <div class="leftmenu_thirdindent">
                                            <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                                            </div>
                                          
                                            <div>
                                                <%=t.t("system.VM")%></div>
                                        </div>
                                    </div>
                                </div>                                
                            </div>
                        </div>
                        
                    </div>
                </div>   
            </div>
        </div>
    </div>
    <!-- Left Menu ends here-->
    </div>
    <div id="footer">
     <div class="footer_testprovisiongtool" id="launch_test" style="display:none">
     	<div class="footer_testprovisiongtool_icon"></div>
        <a href="#">Launch Test Provisioning Tool</a>
     </div>
        <div class="poweredby_box">
        </div>
    </div>
    <!-- Dialogs 1 -->
    <div id="dialog_confirmation" title="Confirmation" style="display: none">
    </div>
    <div id="dialog_info" title="Info" style="display: none">
    </div>
    <div id="dialog_alert" title="Alert" style="display: none">
    </div>
    <div id="dialog_error" title="Error" style="display: none; color: red">
    </div>
    <div id="dialog_session_expired" title="Session Expired" style="display: none">
        <p>
            <%=t.t("your.session.has.expired")%>
        </p>
    </div>
    <div id="dialog_error_internet_not_resolved" title="Error" style="display: none">
        <p style="color: red">
            <%=t.t("internet.name.can.not.be.resolved")%>
        </p>
    </div>
    <div id="dialog_error_management_server_not_accessible" title="Error" style="display: none">
        <p style="color: red">
            <%=t.t("management.server.is.not.accessible")%>
        </p>
    </div>
    <!-- Dialogs 2 -->
    <div id="dialog_info_please_select_one_item_in_middle_menu" title="Alert" style="display: none">
        <p>
            <%=t.t("please.select.at.least.one.item.in.middle.menu")%>
        </p>
    </div>
    <!-- ***** templates (begin) *************************************************************************************************-->
    <div id="leftmenu_secondindent_template" class="leftmenu_expandedlist">
        <div class="leftmenu_content">
            <div class="leftmenu_secondindent">
                <div class="leftmenu_arrows white_nonexpanded_close" id="arrowIcon">
                </div>
                <span id="label"></span>
            </div>
        </div>
    </div>
    
    <div id="midmenu_itemheader_without_margin" class="midmenu_itemheader" style="display:none; ">
    	<p id="name"></p>      
    </div>    
    <div id="midmenu_itemheader_with_margin" class="midmenu_itemheader" style="display:none; margin-top:40px;">
    	<p id="name"></p>       
    </div>    
    
    <div class="midmenu_list" id="midmenu_item" style="display: none;">
        <div class="midmenu_content" id="content">
            <div class="midmenu_icons" id="icon_container" style="display: none">
                <img id="icon" /></div>
            <div class="midmenu_textbox">
                <p title="temp">
                    <strong id="first_row">&nbsp;</strong>
                </p>
                <span title="tmp1" id="second_row_container">
                    <span id="second_row">&nbsp;</span>
                </span>
            </div>
            <div class="midmenu_inactionloader" id="spinning_wheel" style="display: none;">
            </div>
            <div class="midmenu_infoicon" id="info_icon" style="display: none;">
            </div>
            <div class="midmenu_addingfailed_closeicon" id="close_icon" style="display: none;">
            </div>
        </div>
    </div>
    <!-- action list item for middle menu -->
    <li id="action_list_item_middle_menu" style="display: none; width: 94px;"><a id="link"
        href="#">(middle menu action)</a></li>
    <!-- action list item for details tab, subgrid item-->
    <li id="action_list_item" style="display: none;"><a id="link" href="#">(action)</a></li>
    <li id="no_available_actions" style="display: none">
        <%=t.t("no.available.actions")%></li>
    
    <!-- middle menu: no items available (begin) --> 
    <div id="midmenu_container_no_items_available" class="midmenu_emptymsgbox" style="display:none">
        <p>
            No Items Available</p>
    </div>
    <!-- middle menu: no items available (end) --> 
    
    <!-- Zone Template (begin) --> 
    <div class="leftmenu_expandedlist" id="leftmenu_zone_node_template" style="display:none">
     	<div class="leftmenu_loadingbox" style="display:none;" id="loading_container">
        	<div class="leftmenu_loader"></div>
            <p> Adding Zone &hellip; </p>
        </div>
        <div id="row_container">
	        <div class="leftmenu_content" id="header">  
	            <div class="leftmenu_thirdindent">
	                <div class="leftmenu_arrows white_nonexpanded_close" id="zone_arrow">
	                </div>	                
	                <span id="zone_name_label">Zone: </span>
	                <span id="zone_name"></span>
	            </div>  
	        </div>			
            <div id="zone_content" style="display: none">
	            <div id="pods_container">
	            </div>
	            <div id="systemvms_container">
	            </div>
	        </div>
		</div>
    </div>
    <!-- Zone Template (end) -->
	<!-- Pod Template (begin) -->    
    <div class="leftmenu_expandedlist" id="leftmenu_pod_node_template" style="display:none">
    	<div class="leftmenu_loadingbox" style="display:none;"  id="loading_container">
        	<div class="leftmenu_loader"></div>
            <p> Adding Pod &hellip; </p>
        </div>
        <div id="row_container">
	        <div class="leftmenu_content" id="header">
	            <div class="leftmenu_fourthindent">
	                <div class="leftmenu_arrows white_nonexpanded_close" id="pod_arrow">
	                </div>	               
	                <span id="pod_name_label">Pod: </span>
	                <span id="pod_name"></span>
	            </div>
	        </div>	
            <div id="pod_content" style="display: none">
	            <div id="clusters_container">
	            </div>
	        </div>
	    </div>
    </div>
    <!-- Pod Template (end) -->
	<!-- Cluster Template (begin) -->    
    <div class="leftmenu_expandedlist" id="leftmenu_cluster_node_template" style="display:none">
    	<div class="leftmenu_loadingbox" style="display:none;" id="loading_container">
        	<div class="leftmenu_loader"></div>
            <p> Adding Cluster &hellip; </p>
        </div>
        <div id="row_container">
	        <div class="leftmenu_content" id="header">
	            <div class="leftmenu_fifthindent">
	                <div class="leftmenu_arrows white_nonexpanded_close" id="cluster_arrow">
	                </div>	                
	                <span id="cluster_name_label">Cluster: </span>	                
                    <span id="cluster_name"></span>
	            </div>
	        </div>	
			<div id="cluster_content">
	            <div id="hosts_container">
	            </div>
	            <div id="primarystorages_container">
	            </div>
	        </div>
	    </div>
    </div> 
    <!-- Cluster Template (end) -->
    <!-- SystemVM Template (begin) -->
    <div class="leftmenu_expandedlist" id="leftmenu_systemvm_node_template" style="display:none">
    	<div id="row_container">
	        <div class="leftmenu_content" id="header">
	            <div class="leftmenu_fourthindent">
	                <div class="leftmenu_arrows white_nonexpanded_close" id="systemvm_arrow">
	                </div>	             
	                <span id="systemvm_name_label">System VM: </span>
	                <span id="systemvm_name"></span>
	            </div>
	        </div>
        </div>
    </div> 
    <!-- SystemVM Template (end) -->    
    <!-- domain tree node template (begin) -->
    <div id="domain_tree_node_template" style="display:none">    	
                
            <div id="domain_title_container" class="leftmenu_content">
	            <div class="leftmenu_domainindent" id="domain_indent">   
	                <div class="leftmenu_arrows expanded_close" id="domain_expand_icon">
	                </div>
	                <span id="domain_name">
	                    Domain Name</span>
	          	</div>
            </div>                        
            <div id="domain_children_container" style="display: none">
            </div>
   
    </div>
    <!-- domain tree node template (end) -->    
    <!-- ***** templates (end) *************************************************************************************************-->
</body>
</html>
