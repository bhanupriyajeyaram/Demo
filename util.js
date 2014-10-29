/**
 * use dwr.engine.enableLogging function to enable or disable logging
 * 
 * @param should
 *            be true or false
 */
// dwr.engine.enableLogging(false);
window.FSAUtil = {

	isValidEmail : function(email) {
		var emailExpression = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
		return emailExpression.test(email);
	},
	isValidPhonenumber : function(phone) {
		var phoneNumber = /^(\d{1})[\d-]{0,13}(\d{1})$/;
		return phoneNumber.test(phone);
	},
	isValidUserName : function(name) {
		var spclChars = "~`!@#$%^&*()_+=-[]\\\';,./{}|\":<>?";
		for ( var i = 0; i < name.length; i++) {

			if (spclChars.indexOf(name.charAt(i)) != -1) {
				return false;
			}
		}
	},
	 getAppURL:function() {
		return location.protocol + "//" + location.hostname
				+ (location.port && ":" + location.port)
				+ location.pathname.substring(0, location.pathname.indexOf('/', 1))
				+ '/';
	},   
	clearScreen : function() {
		var noOfpage= $("#number-of-pages")[0].selectedIndex;
		var searchString=$("#searchTextid").val();
		jQuery.each(jQuery(":input"),
				function(i, ele) {
					if (!jQuery(ele).attr('disabled')
							|| !jQuery(ele).attr('readOnly')) {
						switch (ele.type.toLowerCase()) {
						case "select-one":
							jQuery(ele)[0].selectedIndex = 0;
							break;
						case "text":
							jQuery(ele).val('');
							break;
						case "password":
							jQuery(ele).val('');
							break;
						case "textarea":
							jQuery(ele).val('');
							break;
						default:
							break;
						}
					}
				});

		$('.pageNumberText').val(pageValue);
		$('#searchTextid').val(searchString);
		$("#number-of-pages")[0].selectedIndex = noOfpage;
	},

};
