(function($){

   $(document).ready(function(){
      $('[data-toggle="tooltip"]').tooltip();
      $('form').validate({'ignore':'.ignore-validation'});

      $('.profile-item').click(function(evt){
         console.log('Selected a profile: '+$(this).text());
         let dd=$(this).parents('div.dropdown:first');
         $(dd).find('button:first').text($(this).text());
         $('input:first').val($(this).attr('value'));

         let profile=$(this).attr('value');
         if(profile=='')profile='-1';
         let found=false;
         for(var i=0; i<profiles.length; i++)
            if(profiles[i]['index']==profile){
               profile=profiles[i];
               found=true;
               break;
            }

         $('form#connect').trigger('reset');
         $('.fld-private-key').show();
         $('.fld-password').show()
         $('input[type=text],input[type=password],input[type=number]').val('').removeAttr('readonly');
         if(found){
            $('input[name=profile]').val(profile['index']);
            if(profile['host'])$('input[name=hostname]').val('somewhere.com').attr('readonly', 'readonly');
            if(profile['port'])$('input[name=port]').val('65535').attr('readonly', 'readonly');
            if(profile['username'])$('input[name=username]').val('somebody').attr('readonly', 'readonly');
            if(profile['private-key']){
               $('.fld-private-key').hide();
               $('input[name=passphrase]').focus().select();
               $('.fld-password').hide()
            }else{
               $('input[name=password]').focus().select();
            }
         }

         if(Boolean(Cookies.get('acceptCookies'))){
            console.debug('Store the profile: '+profile['index']+' - '+profile['name']);
            let expired=new Date();
            expired.setTime(expired.getTime()*30*86400000); //expired=now+30days; 86400000=1000*60*60*24
            Cookies.set('profileIndex', profile['index'], {'expires':expired, 'path':'/'});
            Cookies.set('profileName', profile['name'], {'expires':expired, 'path':'/'});
         }

         return this;
      });

      
      let lastIndex=Cookies.get('profileIndex');
      let lastName =Cookies.get('profileName');
      if(Boolean(Cookies.get('acceptCookies')) && lastIndex!=undefined && lastName!=undefined){
         console.debug('Restore the last selected profile: '+lastIndex+' - '+lastName);
         let found=false;
         $('.profile-item').each(function(idx, val){
            if($(this).attr('value')==lastIndex && $(this).text()==lastName){
               found=true;
               $(this).trigger('click');
               console.info('Restored the last profile['+lastIndex+'] - '+lastName);
            }
         });
         if(!found)console.info('Profile index and name mismatched!');
      }

      console.log('/static/js/profiles.js loaded');
   });
})(jQuery);
